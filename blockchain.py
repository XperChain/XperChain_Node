import pandas as pd
import math

import streamlit as st
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone

import hashlib, json, base64
from ecdsa import VerifyingKey, VerifyingKey, BadSignatureError, SigningKey, SECP256k1

# 블록 생성 주기
block_time_in_min = 1

# 거래 수수료
transaction_fee = 1

# 블록 해시 함수
def hash_block(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

# 서명 검증 함수
def verify_signature(tx):
    try:
        tx_copy = dict(tx)
        signature_b64 = tx_copy.pop("signature", None)
        if not signature_b64:
            return False

        tx_string = json.dumps(tx_copy, sort_keys=True).encode()
        tx_hash = hashlib.sha256(tx_string).digest()

        public_key_hex = tx["sender"]
        public_key_bytes = bytes.fromhex(public_key_hex)

        if len(public_key_bytes) != 64:
            return False  # SECP256k1 expects uncompressed 64-byte public key

        vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        signature = base64.b64decode(signature_b64)

        return vk.verify(signature, tx_hash)

    except (BadSignatureError, ValueError, KeyError):
        return False

# 서명 함수
def sign_transaction(private_key, tx_data):
    tx_copy = dict(tx_data)
    tx_string = json.dumps(tx_copy, sort_keys=True).encode()
    tx_hash = hashlib.sha256(tx_string).digest()

    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    signature = sk.sign(tx_hash)

    return base64.b64encode(signature).decode()

# 지갑 생성 함수
def generate_wallet():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    private_key = sk.to_string().hex()      # 32바이트 개인키 → hex 문자열
    public_key = vk.to_string().hex()       # 64바이트 공개키 → hex 문자열 (압축X)

    return public_key, private_key

# 잔고 확인 함수
def get_balance(address, blocks):
    balance = 0
    for blk in blocks.find().sort("index"):
        for tx in blk["transactions"]:
            if tx["sender"] == address:
                balance -= tx["amount"]
            if tx["recipient"] == address:
                balance += tx["amount"]
    return balance

# 블록 보상 계산 함수
def get_block_reward(block_height):
    R0 = 10000                   # 초기 보상 
    halving_block = 1_000_000    # 반감기
    decay_factor = math.log(2) / halving_block 
    reward = round(R0 * math.exp(-decay_factor * block_height))
    return max(0, reward)

# 블록 생성 함수
def create_block(transactions, previous_hash="0"):
    block = {
        "index": blocks.count_documents({}) + 1,
        "timestamp": time.time(),
        "transactions": transactions,
        "previous_hash": previous_hash
    }
    block["hash"] = hash_block(block)
    return block

# 블록 생성 검증 함수
def auto_generate_block_if_needed(blocks, tx_pool, block_time_in_min, miner_address=None, display=False):
    last_block = blocks.find_one(sort=[("index", -1)])
    last_time = datetime.fromtimestamp(last_block["timestamp"]) if last_block else datetime.min

    utc_now = datetime.utcnow()
    now = utc_now + timedelta(hours=9)

    if display:
        st.write(f"마지막 블록 {last_time}, 지금 시간 {now}")

    if now - last_time >= timedelta(minutes=block_time_in_min):
        raw_txs = list(tx_pool.find({}))
        transactions = []
        invalid_txs = []
        temp_balances = {}

        total_fees = 0.0  # ← 모든 트랜잭션의 수수료 합계
        for tx in raw_txs:
            tx = dict(tx)
            tx.pop("_id", None)

            sender = tx["sender"]
            recipient = tx["recipient"]
            amount = tx["amount"]
            fee = tx.get("fee", 0.0)

            if sender == "SYSTEM":
                transactions.append(tx)
                continue

            if not verify_signature(tx):
                if display:
                    st.warning(f"❌ 무효 트랜잭션 - 서명 검증 실패: {sender[:10]}...")
                invalid_txs.append(tx)
                continue

            temp_balances[sender] = temp_balances.get(sender, get_balance(sender, blocks))
            if temp_balances[sender] < amount + fee:
                if display:
                    st.warning(f"❌ 무효 트랜잭션 - 잔고 부족: {sender[:10]}...")
                invalid_txs.append(tx)
                continue

            # 유효한 트랜잭션 처리
            temp_balances[sender] -= (amount + fee)
            temp_balances[recipient] = temp_balances.get(recipient, get_balance(recipient, blocks)) + amount
            total_fees += fee
            transactions.append(tx)

        # 블록 인덱스
        new_index = last_block["index"] + 1 if last_block else 1

        # 보상 합계 준비
        reward = get_block_reward(new_index)
        total_fees = 0
        valid_txs = []
        invalid_txs = []
        system_tx_count = 0

        # 임시 잔고 계산용
        temp_balances = {}

        for tx in raw_txs:
            tx = dict(tx)
            tx.pop("_id", None)

            sender = tx["sender"]
            recipient = tx["recipient"]
            amount = tx["amount"]
            fee = tx.get("fee", 0)

            if sender == "SYSTEM":
                system_tx_count += 1
                expected = reward + total_fees
                if amount != expected:
                    if display:
                        st.warning(f"❌ SYSTEM 보상 금액 불일치: 예상={expected}, 실제={amount}")
                    invalid_txs.append(tx)
                else:
                    valid_txs.append(tx)
                continue

            if not verify_signature(tx):
                if display:
                    st.warning(f"❌ 서명 검증 실패: {sender[:10]}...")
                invalid_txs.append(tx)
                continue

            temp_balances[sender] = temp_balances.get(sender, get_balance(sender, blocks))
            if temp_balances[sender] < amount + fee:
                if display:
                    st.warning(f"❌ 잔고 부족: {sender[:10]}...")
                invalid_txs.append(tx)
                continue

            # 유효한 거래
            temp_balances[sender] -= (amount + fee)
            temp_balances[recipient] = temp_balances.get(recipient, get_balance(recipient, blocks)) + amount
            total_fees += fee
            valid_txs.append(tx)

        # SYSTEM 트랜잭션이 2개 이상이면 모두 제거
        if system_tx_count >=1:
            if display:
                st.warning(f"⚠️ SYSTEM 트랜잭션이 {system_tx_count}개 존재합니다. 모두 무시하고 새 보상 트랜잭션만 생성됩니다.")
            # SYSTEM이 포함된 트랜잭션 제거
            valid_txs = [tx for tx in valid_txs if tx.get("sender") != "SYSTEM"]
            invalid_txs += [tx for tx in raw_txs if tx.get("sender") == "SYSTEM"]


        # 블록 생성 조건 확인
        now = datetime.utcnow() + timedelta(hours=9)
        if now - last_time < timedelta(minutes=block_time_in_min):
            if display:
                st.info("⏳ 블록 생성 조건(시간)이 충족되지 않았습니다.")
            return

        # SYSTEM 보상 트랜잭션 생성
        if (reward > 0 or total_fees > 0) and miner_address:
            coinbase_tx = {
                "sender": "SYSTEM",
                "recipient": miner_address,
                "amount": reward + total_fees,
                "timestamp": now.timestamp(),
                "signature": "coinbase"
            }
            valid_txs.insert(0, coinbase_tx)

        # 블록 생성
        new_block = {
            "index": new_index,
            "timestamp": now.timestamp(),
            "transactions": valid_txs,
            "previous_hash": last_block["hash"] if last_block else "0"
        }
        new_block["hash"] = hash_block(new_block)
        blocks.insert_one(new_block)

        # 트랜잭션 풀 정리
        for tx in valid_txs + invalid_txs:
            tx_pool.delete_one({
                "sender": tx["sender"],
                "recipient": tx["recipient"],
                "amount": tx["amount"],
                "timestamp": tx["timestamp"],
                "signature": tx["signature"]
            })

        if display:
            st.success(f"✅ 블록 생성됨: #{new_block['index']} | 트랜잭션 수: {len(valid_txs)} | 보상: {reward} + 수수료 {total_fees}")

    else:
        if display:
            st.info("⏳ 블록 생성 조건(1분)이 충족되지 않았습니다.")

# 합의 알고리즘
# [사용자 버튼 클릭]
#     ↓
# [노드들로부터 체인 길이 수집]
#     ↓
# [긴 노드 → 블록 정합성 확인]
#      ↓
# [필요한 블록만 가져오기]
#     ↓
# [각 블록의 트랜잭션 검증 및 추가]
#      ↓
# [분기 블록 기록 → 추후 비교 및 처리]
#      ↓
# [내 체인 시간 ≥ 1분 → 블록 생성 및 추가]

def consensus_protocol(blocks, peers, tx_pool, block_time_in_min, miner_address, display=False):
    if display:
        st.subheader("🔍 [합의 시작]")
        st.write("1️⃣ 사용자 요청에 따라 블록 생성 절차를 시작합니다.")

    # 현재 내 체인 정보
    my_last_block = blocks.find_one(sort=[("index", -1)])
    my_last_index = my_last_block["index"] if my_last_block else -1
    my_last_hash = my_last_block["hash"] if my_last_block else "0"
    my_len = blocks.count_documents({})
    forked_blocks = []
    
    if display:
        st.write(f"📦 현재 내 체인 길이: {my_len}, 마지막 인덱스: {my_last_index}")

    # 각 피어 체인 확인
    for peer in peers.find():
        try:
            peer_uri = peer["uri"]
            if display:
                st.info(f"🌐 피어 연결 시도: {peer_uri}")
            peer_client = MongoClient(peer_uri)
            peer_db = peer_client["blockchain_db"]
            peer_blocks = peer_db["blocks"]
            peer_len = peer_blocks.count_documents({})
            
            if display:
                st.write(f"🔗 피어 체인 길이: {peer_len}")

            if peer_len > my_len:  # 2. 더 긴 체인 존재
                if display:
                    st.info("📏 피어의 체인이 더 깁니다. 블록 일치 여부 확인 중...")

                same_block = peer_blocks.find_one({"index": my_last_index})     
                if my_len==0 or (same_block and same_block["hash"] == my_last_hash ):  # 3. 블록 일치 확인
                    if display:
                        st.success("✅ 마지막 블록이 일치하거나 내 블록이 초기화된 경우 입니다. 새로운 블록만 가져옵니다.")
                        
                    new_blocks = list(peer_blocks.find({"index": {"$gt": my_last_index}}).sort("index"))  # 4                    
                    for blk in new_blocks:
                        blk_time = datetime.fromtimestamp(blk["timestamp"])
                        if (datetime.utcnow() + timedelta(hours=9)) - blk_time >= timedelta(minutes=block_time_in_min):
                            valid = True
                            system_tx_count = 0  # SYSTEM 트랜잭션 수 카운터

                            for tx in blk["transactions"]:
                                if tx["sender"] == "SYSTEM":
                                    system_tx_count += 1
                                    expected_reward = get_block_reward(blk["index"])
                                    if tx["amount"] != expected_reward:
                                        if display:
                                            st.warning(f"❌ SYSTEM 보상 금액 불일치 (예상: {expected_reward}, 실제: {tx['amount']})")
                                        valid = False
                                        break
                                else:
                                    if not verify_signature(tx):
                                        if display:
                                            st.warning("❌ 서명 검증 실패")
                                        valid = False
                                        break
                                    if get_balance(tx["sender"], blocks) < tx["amount"] + tx.get("fee", 0):
                                        if display:
                                            st.warning("❌ 잔고 부족")
                                        valid = False
                                        break

                            if system_tx_count > 1:
                                if display:
                                    st.warning("🚫 SYSTEM 트랜잭션이 1개를 초과합니다.")
                                valid = False

                            if valid:
                                blocks.insert_one(blk)
                                for tx in blk["transactions"]:
                                    tx_pool.delete_one({
                                        "sender": tx["sender"],
                                        "timestamp": tx["timestamp"]
                                    })
                                if display:
                                    st.success(f"📥 블록 #{blk['index']} 동기화 완료")
                        else:
                            if display:
                                st.info(f"⏳ 블록 #{blk['index']}은 생성 시간 기준 조건({block_time_in_min}분 경과)을 만족하지 않음")           
                else:
                    if display:
                        st.warning("⚠️ 마지막 블록이 불일치합니다. 분기 체인으로 처리합니다.")
                    forked = list(peer_blocks.find({"index": {"$gt": my_last_index}}).sort("index"))
                    forked_blocks.extend(forked)  # 6
        except Exception as e:
            if display:
                st.warning(f"❌ 피어 접근 실패: {e}")

    # 분기 체인 처리
    if forked_blocks:
        if display:
            st.subheader("🌿 [분기 체인 처리]")
        for blk in forked_blocks:
            blk_time = datetime.fromtimestamp(blk["timestamp"])
            if (datetime.utcnow()+ timedelta(hours=9)) - blk_time >= timedelta(minutes=block_time_in_min):
                for tx in blk["transactions"]:
                    tx_exists_in_chain = blocks.find_one({
                        "transactions.timestamp": tx["timestamp"],
                        "transactions.sender": tx["sender"]
                    })
                    tx_exists_in_pool = tx_pool.find_one({
                        "timestamp": tx["timestamp"],
                        "sender": tx["sender"]
                    })
                    
                    if not tx_exists_in_chain and not tx_exists_in_pool:
                        if tx["sender"] == "SYSTEM":
                            expected_reward = get_block_reward(blk["index"])
                            if tx["amount"] == expected_reward:
                                tx_pool.insert_one(tx)
                                if display:
                                    st.info(f"🎁 보상 트랜잭션 추가됨: {tx['recipient']} ({tx['amount']})")
                            else:
                                if display:
                                    st.warning(f"❌ SYSTEM 보상 불일치: 예상={expected_reward}, 실제={tx['amount']}")
                        elif verify_signature(tx) and get_balance(tx["sender"], blocks) >= tx["amount"]:
                            tx_pool.insert_one(tx)
                            if display:
                                st.info(f"🔄 분기 트랜잭션 추가: {tx['sender']} → {tx['recipient']} ({tx['amount']})")
                        else:
                            if display:
                                st.warning("❌ 트랜잭션 유효성 검증 실패 (서명 또는 잔고)")
                    elif tx_exists_in_pool:
                        if display:
                            st.info(f"⚠️ 이미 트랜잭션 풀에 존재: {tx['sender']} ({tx['amount']})")

    # 8. 마지막 블록 1분 경과 시 블록 생성
    if display:
        st.subheader("🏗️ [블록 생성 확인]")
        
    auto_generate_block_if_needed(blocks, tx_pool, block_time_in_min, miner_address = miner_address)

    if display:
        st.success("🎉 합의 프로토콜 완료")