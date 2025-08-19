import streamlit as st
import json
# 페이지 설정
st.set_page_config(page_title="로그 기반 스토리텔링", layout="centered")

# 메인 컨테이너
with st.container():
    st.markdown('<div class="centered">', unsafe_allow_html=True)

    st.markdown("## 로그기반 스토리텔링")
    st.markdown("시작하시려면 로그파일 업로드 해주세요.")

    # 텍스트 입력

    # 파일 업로드
    uploaded_file = st.file_uploader("", type=["txt", "log", "csv", "json"])

    st.markdown("</div>", unsafe_allow_html=True)

# 입력 확인

if uploaded_file is not None:
    st.write("업로드한 파일명:", uploaded_file.name)
    try:
        data = json.load(uploaded_file)
        st.session_state['log_data'] = data  # 세션 상태에 저장
        st.success("파일 업로드 완료")
        
    except Exception as e:
        st.error(f"파일 처리 중 오류 발생: {e}")
else:
    st.info("로그 파일을 업로드해야 분석을 시작할 수 있습니다.")

