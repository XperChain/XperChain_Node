from pymongo import MongoClient
from datetime import datetime
import streamlit as st

def import_peers_from_seed(seed_uri, my_uri, local_peers_collection, display=False):
    """
    Seed 노드의 peers 컬렉션에서 새로운 peer들을 가져와 local peers에 추가합니다.
    내 URI(my_uri)는 제외되며, seed_uri도 다를 경우 peers에 추가됩니다.
    
    Parameters:
        seed_uri (str): Seed 노드의 MongoDB URI
        my_uri (str): 현재 내 노드의 URI (이 URI는 peers에 추가하지 않음)
        local_peers_collection: 현재 노드의 MongoDB peers 컬렉션 객체
        display (bool): Streamlit 출력 메시지 활성화 여부
        
    Returns:
        List[str]: 추가된 peer들의 URI 목록
    """
    try:
        # 1. Seed 노드 접근
        seed_client = MongoClient(seed_uri)
        seed_peers = seed_client["blockchain_db"]["peers"]
        seed_peer_list = list(seed_peers.find({}, {"_id": 0}))

        if display:            
            st.info(f"🌐 Seed 노드 접근 성공: {seed_uri}")

        # 2. 내 peers 컬렉션에서 기존 URI 수집
        my_peer_uris = set(p["uri"] for p in local_peers_collection.find({}, {"_id": 0, "uri": 1}))
        my_peer_uris.add(my_uri)  # 내 URI는 추가 금지

        new_peers = []

        # 3. Seed peers 중 중복되지 않고 내 URI가 아닌 경우만 추가
        for peer in seed_peer_list:
            uri = peer.get("uri")
            if uri and uri not in my_peer_uris:
                peer["timestamp"] = datetime.now()
                local_peers_collection.insert_one(peer)
                new_peers.append(uri)
                if display: 
                    st.write(f"added {new_peers}")

        # 4. Seed URI 자체도 내 URI와 다르고 아직 등록되지 않았다면 추가
        if seed_uri not in my_peer_uris:
            if seed_uri not in my_uri:
                seed_peer_data = {
                    "public_key": "seed",  # 필요 시 수정 가능
                    "uri": seed_uri,
                    "timestamp": datetime.now()
                }
                local_peers_collection.insert_one(seed_peer_data)
                new_peers.append(seed_uri)
                if display: 
                    st.write(f"seed uri {seed_uri} my uri {my_uri}")

        # 5. 결과 출력
        if display:            
            if new_peers:                
                st.success(f"✅ {len(new_peers)}개의 peer가 새로 추가되었습니다.")
                for uri in new_peers:                    
                    st.markdown(f"- `{uri}`")
            else:
                st.info("ℹ️ 새로 추가된 peer가 없습니다.")

        return new_peers

    except Exception as e:
        if display:            
            st.error(f"❌ Seed 노드 연결 실패: {e}")
        return []
