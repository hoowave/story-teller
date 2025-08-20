import streamlit as st
import requests
import json

# 페이지 설정
st.set_page_config(page_title="로그 기반 스토리텔링", layout="centered")

# 메인 컨테이너
with st.container():
    st.markdown('<div class="centered">', unsafe_allow_html=True)
    st.markdown("## 로그기반 스토리텔링")
    st.markdown("시작하시려면 로그파일을 업로드 해주세요. (다중 업로드 가능)")

    # 다중 파일 업로드
    uploaded_files = st.file_uploader(
        "",
        type=["txt", "log", "csv", "json"],
        accept_multiple_files=True
    )

    st.markdown("</div>", unsafe_allow_html=True)

# 입력 확인
if uploaded_files:
    st.write("업로드한 파일명:", [file.name for file in uploaded_files])
    st.write("업로드한 파일 수:", len(uploaded_files))
    try:
        # 여러 파일을 서버로 전송
        files = [("files", (file.name, file.getvalue())) for file in uploaded_files]

        # 백엔드 서버로 POST 요청 (localhost:8000 예시)
        response = requests.post("http://localhost:8000/upload", files=files)

        if response.status_code == 200:
            st.success("파일 업로드 및 서버 전송 성공")
            try:
                result = response.json()
                st.json(result)
            except Exception:
                st.write("서버 응답:", response.text)
        else:
            st.error(f"서버 오류 발생: {response.status_code} - {response.text}")

    except Exception as e:
        st.error(f"파일 처리 중 오류 발생: {e}")
else:
    st.info("로그 파일을 업로드해야 분석을 시작할 수 있습니다.")
