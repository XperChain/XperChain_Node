import streamlit as st
from pymongo import MongoClient
import secrets

import hashlib, json
import time
import pandas as pd
from io import BytesIO
from PIL import Image
from datetime import datetime, timedelta, timezone
import cv2
import numpy as np
import qrcode
import base64
from ecdsa import SigningKey, SECP256k1

from blockchain import *
from import_peers_from_seed import import_peers_from_seed

# 타임스탬프 설정값
KST = timezone(timedelta(hours=9))  # 한국 시간대 설정

# DB 설정
MONGO_URL = st.secrets["mongodb"]["uri"]
MONGO_READ_URL = st.secrets["mongodb_read"]["uri"]
MONGO_SEED_READ_URL = st.secrets["mongodb_seed_read"]["uri"]
miner_wallet = st.secrets["miner"]["public_key"]
miner_key = st.secrets["miner"]["private_key"]


client = MongoClient(MONGO_URL)
db = client["blockchain_db"]
blocks = db["blocks"]
tx_pool = db["transactions"]
users = db["users"]
peers = db['peers']

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 초기 상태
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None
if "balance" not in st.session_state:
    st.session_state["balance"] = 0.0

# 로그인 및 회원가입
if not st.session_state["logged_in_user"]:
    with st.expander("로그인", expanded=True):

        # 이전 모드 기억용 변수
        if "auth_mode_last" not in st.session_state:
            st.session_state["auth_mode_last"] = "로그인"

        auth_mode = st.radio("", ["로그인", "회원가입"], horizontal=True, key="auth_mode")

        # 모드가 바뀌면 입력 필드 초기화
        if auth_mode != st.session_state["auth_mode_last"]:
            st.session_state["auth_mode_last"] = auth_mode
            st.session_state["username"] = ""
            st.session_state["password"] = ""

        # 입력 필드 with 세션 상태 연결
        username = st.text_input("👤 사용자", key="username")
        password = st.text_input("🔑 비밀번호", type="password", key="password")

        if auth_mode == "회원가입":
            private_key_input = st.text_input("🔐 지갑 개인키(미입력 시 자동 생성)", key="private_key_input")

            if st.button("✅ 회원가입"):
                if username == "" or password == "":
                    st.warning("모든 필드를 입력하세요.")
                elif len(username) < 5:
                    st.warning("사용자 명칭은 최소 5자리 이상이어야 합니다.")
                elif len(password) < 8:
                    st.warning("비밀번호는 최소 8자리 이상이어야 합니다.")
                elif users.find_one({"username": username}):
                    st.error("이미 존재하는 사용자입니다.")
                else:
                    # 개인키 수동 입력 여부 확인
                    if private_key_input.strip():
                        try:
                            sk = SigningKey.from_string(bytes.fromhex(private_key_input), curve=SECP256k1)
                            pub = sk.get_verifying_key().to_string().hex()
                            priv = private_key_input
                        except Exception as e:
                            st.error(f"❌ 개인키 형식 오류: {e}")
                            st.stop()
                    else:
                        # 자동 생성
                        pub, priv = generate_wallet()

                    users.insert_one({
                        "username": username,
                        "password_hash": hash_password(password),
                        "public_key": pub,
                        "private_key": priv
                    })
                    st.success("🎉 회원가입 성공! 이제 로그인 해보세요.")

                  

        elif auth_mode == "로그인":
            if st.button("🔓 로그인"):
                user = users.find_one({"username": username})
                if not user or user["password_hash"] != hash_password(password):
                    st.error("❌ 사용자 또는 비밀번호가 틀렸습니다.")
                else:                    
                    added_peers = import_peers_from_seed(
                        seed_uri=MONGO_SEED_READ_URL,
                        my_uri=MONGO_READ_URL,
                        local_peers_collection=peers,  # 현재 내 peers 컬렉션 (MongoDB)                        
                    )

                    # 필요시 추가 처리
                    if added_peers:
                        st.info(f"🔄 총 {len(added_peers)}개 peer가 추가되었습니다.")
                
                    consensus_protocol(blocks, peers, tx_pool, block_time_in_min, miner_wallet, display = False)
                    
                    st.session_state["logged_in_user"] = user
                    st.session_state["balance"] = get_balance(user["public_key"], blocks)
                    #st.success(f"환영합니다, {username}님!")
                    st.rerun()

if not st.session_state["logged_in_user"]:
    st.stop()

    
# 사용자 세션 정보
user = st.session_state["logged_in_user"]
public_key = user["public_key"]
private_key = user["private_key"]

with st.expander("📂 내 지갑 정보", expanded=True):  # 기본 펼쳐짐
    st.markdown(f"👤 사용자: `{user['username']}`")

    # QR 생성 상태 관리
    if "qr_generated" not in st.session_state:
        st.session_state["qr_generated"] = False

    col1, col2 = st.columns([4, 1], gap="small")

    with col1:
        st.success(f"🪪 지갑 공개키(주소): {public_key}")

    with col2:
        if not st.session_state["qr_generated"]:
            if st.button("📤 QR 생성", key="generate_qr_btn"):
                st.session_state["qr_generated"] = True
                st.rerun()

        if st.session_state["qr_generated"]:
            qr_img = qrcode.make(public_key)
            buf = BytesIO()
            qr_img.save(buf, format="PNG")
            st.image(buf.getvalue(), width=300)

    # 잔고 표시
    st.success(f"💰 잔고: {st.session_state['balance']:.2f}")
    
    if st.button("🔒 로그아웃", key="logout_btn"):
        st.session_state["logged_in_user"] = None
        st.rerun()

# 트랜잭션
# QR 스캔 상태 초기화
if "qr_scan_requested" not in st.session_state:
    st.session_state["qr_scan_requested"] = False
if "recipient_scanned" not in st.session_state:
    st.session_state["recipient_scanned"] = ""

with st.expander("📤 트랜잭션 전송", expanded=False):
    col1, col2 = st.columns([4, 1], gap="small")

    with col1:
        recipient = st.text_input(
            "📨 받는 사람의 공개키(주소)",
            value=st.session_state.get("recipient_scanned", ""),
            key="recipient_input"
        )

    with col2:
        st.write("")
        st.write("")
        if st.button("📷 QR 스캔", key="qr_scan_btn"):
            st.session_state["qr_scan_requested"] = True

    # QR 스캔
    if st.session_state.get("qr_scan_requested", False):
        if st.button("❌ 스캔 취소", key="cancel_qr_btn"):
            st.session_state["qr_scan_requested"] = False
            st.rerun()
        image_file = st.camera_input("📸 QR 코드를 카메라로 스캔하세요")
        if image_file:
            image = Image.open(image_file).convert("RGB")
            img_np = np.array(image)
            qr_decoder = cv2.QRCodeDetector()
            data, points, _ = qr_decoder.detectAndDecode(img_np)
            if data:
                st.session_state["recipient_scanned"] = data
                st.session_state["qr_scan_requested"] = False
                st.success("✅ QR 코드 인식 성공!")
                st.rerun()
            else:
                st.error("❌ QR 코드 인식에 실패했습니다.")

    amount = st.number_input("💸 이체 금액", min_value=0.0, key="amount_input")
    st.info(f"💰 전송 수수료: {transaction_fee:.2f}")    
    
    col1, col2 = st.columns([1, 1], gap="small")
    with col1:
        if st.button("➕ 트랜잭션 전송(이체)"):
            recipient_value = st.session_state["recipient_input"]
            amount_value = st.session_state["amount_input"]

            if recipient_value.strip() == "" or amount_value <= 0:
                st.warning("모든 필드를 입력하세요.")
            elif amount_value + transaction_fee > st.session_state["balance"]:
                st.error("❌ 잔고 부족 (수수료 포함)")
            else:
                tx_data = {
                    "sender": public_key,
                    "recipient": recipient_value,
                    "amount": amount_value,
                    "fee": transaction_fee,
                    "timestamp": time.time()
                }
                tx_data["signature"] = sign_transaction(private_key, tx_data)
                tx_pool.insert_one(tx_data)                
                consensus_protocol(blocks, peers, tx_pool, block_time_in_min, miner_wallet, display = False)
                st.success("✅ 트랜잭션이 추가되었습니다.")                               
                st.rerun()
                
    with col2:
        col11, col12 = st.columns([1, 1], gap="small")
        with col11:
            # 트랜잭션 풀에 거래가 있을 때만 버튼 표시
            if tx_pool.count_documents({}) > 0:
                if st.button("⛏️ Airdrop 보상"):
                    airdrop_value = 10
                    tx_data = {
                        "sender": miner_wallet,
                        "recipient": public_key,
                        "amount": airdrop_value,
                        "fee": transaction_fee,
                        "timestamp": time.time()
                    }
                    tx_data["signature"] = sign_transaction(miner_key, tx_data)
                    tx_pool.insert_one(tx_data)                
                    consensus_protocol(blocks, peers, tx_pool, block_time_in_min, miner_wallet, display = False)
                
        with col12:  
            if tx_pool.count_documents({}) > 0:
                last_block = blocks.find_one(sort=[("index", -1)]) 
                if last_block:
                    last_time = datetime.fromtimestamp(last_block["timestamp"])
                    now = datetime.utcnow() + timedelta(hours=9)

                    elapsed = now - last_time
                    remaining = timedelta(minutes=block_time_in_min) - elapsed
                    if remaining.total_seconds() > 0:
                        st.info(f"⏳ 다음 Airdrop 보상까지 남은 시간: {str(remaining).split('.')[0]}")
                else:
                    st.info("ℹ️ 아직 블록체인이 시작되지 않았습니다.")        
            
with st.expander("📥 트랜잭션 풀", expanded=False):
    txs = list(tx_pool.find().sort("timestamp", -1))

    if txs:
        table_data = []
        for tx in txs:
            sender = tx.get("sender", "")
            recipient = tx.get("recipient", "")
            amount = tx.get("amount", 0.0)
            fee = tx.get("fee", 0.0)
            total = amount + fee
            time_str = datetime.fromtimestamp(tx["timestamp"], tz=KST).strftime('%Y-%m-%d %H:%M:%S')

            # 입출금 방향 계산
            if sender == public_key:
                sign = "-"
                direction = "출금"
            elif recipient == public_key:
                sign = "+"
                direction = "입금"
            else:
                sign = ""
                direction = "기타"

            table_data.append({
                "보낸 사람": sender[:5] + "...",
                "받는 사람": recipient[:5] + "...",
                "금액": f"{sign}{amount:.2f}" if sign else f"{amount:.2f}",
                "수수료": f"{sign}{fee:.2f}" if sign else f"{fee:.2f}",
                "총합": f"{sign}{total:.2f}" if sign else f"{total:.2f}",                
                "시간": time_str,
                "구분": direction
            })

        df = pd.DataFrame(table_data)

        def highlight_signed(val):
            if isinstance(val, str) and val.startswith('+'):
                return 'color: green; font-weight: bold'
            elif isinstance(val, str) and val.startswith('-'):
                return 'color: red; font-weight: bold'
            return ''

        styled_df = df.style.applymap(highlight_signed, subset=["금액", "수수료", "총합"])
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("트랜잭션 풀이 비어 있습니다.")


with st.expander("📚 전체 거래 내역", expanded=False):
    personal_txs = []
    for blk in blocks.find().sort("index", -1):
        for tx in blk.get("transactions", []):
            sender = tx.get("sender", "")
            recipient = tx.get("recipient", "")
            amount = tx.get("amount", 0.0)
            fee = tx.get("fee", 0.0)
            total = amount + fee
            ts = tx.get("timestamp")
            time_str = datetime.fromtimestamp(ts, tz=KST).strftime('%Y-%m-%d %H:%M:%S') if ts else "없음"

            # 내 공개키 관련된 트랜잭션만 추출
            if public_key not in (sender, recipient):
                continue

            if sender == public_key:
                sign = "-"
                direction = "출금"
            elif recipient == public_key:
                sign = "+"
                direction = "입금"
            else:
                sign = ""
                direction = ""

            personal_txs.append({
                "블록": blk["index"],
                "보낸 사람": sender[:5] + "...",
                "받는 사람": recipient[:5] + "...",
                "금액": f"{sign}{amount:.2f}",
                "수수료": f"{sign}{fee:.2f}",
                "총합": f"{sign}{total:.2f}",
                "시간": time_str,
                "구분": direction
            })

    if personal_txs:
        df = pd.DataFrame(personal_txs)

        def highlight_direction(val):
            if isinstance(val, str) and val.startswith('+'):
                return 'color: green; font-weight: bold'
            elif isinstance(val, str) and val.startswith('-'):
                return 'color: red; font-weight: bold'
            return ''

        styled_df = df.style.applymap(highlight_direction, subset=["금액", "수수료", "총합"])
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("📭 내 거래 기록이 없습니다.")


# ⛓️ 블록체인 보기
with st.expander("⛓️ 블록체인 탐색기", expanded=False):
    # 📌 최신 블록 번호 가져오기
    latest_block = blocks.find_one(sort=[("index", -1)])    

    if latest_block is None:
        st.warning("📭 아직 블록체인이 생성되지 않았습니다.")
    else:    
        latest_index = latest_block["index"] if latest_block else 1

        # 🔍 블록 번호 입력 (기본값 = 최신 블록 번호)
        search_index = st.number_input("🔍 블록 번호로 검색", min_value=1, step=1, value=latest_index, format="%d")

        block = blocks.find_one({"index": search_index})
        if block:
            # 📋 블록 정보 표
            block_info = pd.DataFrame({
                "속성": ["블록 번호", "해시", "이전 해시", "생성 시간", "트랜잭션 수"],
                "값": [
                    block.get("index"),
                    block.get("hash", "")[:10] + "...",
                    block.get("previous_hash", "")[:10] + "...",
                    datetime.fromtimestamp(block.get("timestamp", time.time()), tz=KST).strftime('%Y-%m-%d %H:%M:%S'),
                    len(block.get("transactions", []))
                ]
            })

            st.markdown("#### 📋 블록 정보")
            st.dataframe(block_info, use_container_width=True)

            # 📦 트랜잭션 목록
            transactions = block.get("transactions", [])
            if not transactions:
                st.info("📭 이 블록에는 트랜잭션이 없습니다.")
            else:
                tx_table = []
                for tx in transactions:
                    ts = tx.get("timestamp")
                    time_str = datetime.fromtimestamp(ts, tz=KST).strftime('%Y-%m-%d %H:%M:%S') if ts else "없음"

                    amount = tx.get("amount", 0.0)
                    fee = tx.get("fee", 0.0)
                    total = amount + fee

                    tx_table.append({
                        "보낸 사람": tx.get("sender", "")[:5] + "...",
                        "받는 사람": tx.get("recipient", "")[:5] + "...",
                        "금액": amount,
                        "수수료": fee,
                        "총합": total,
                        "서명": tx.get("signature", "")[:5] + "...",
                        "시간": time_str
                    })
                st.markdown("#### 📦 트랜잭션 목록")
                st.dataframe(pd.DataFrame(tx_table), use_container_width=True)

        else:
            st.info("❗ 해당 번호의 블록을 찾을 수 없습니다.")

