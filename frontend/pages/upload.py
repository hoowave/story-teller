import streamlit as st
# 페이지 설정
st.set_page_config(page_title="로그 기반 스토리텔링", page_icon="📘", layout="centered")

# 메인 컨테이너
with st.container():
    st.markdown('<div class="centered">', unsafe_allow_html=True)

    st.markdown("## 로그기반 스토리텔링")
    st.markdown("시작하시려면 로그파일 업로드 혹은 텍스트를 입력해주세요.")

    # 텍스트 입력
    user_text = st.text_input("", placeholder="로그 텍스트를 입력해주세요")

    # 파일 업로드
    uploaded_file = st.file_uploader("", type=["txt", "log", "csv", "json"])

    st.markdown("</div>", unsafe_allow_html=True)

# 입력 확인
if user_text:
    st.write("입력한 텍스트:", user_text)

if uploaded_file is not None:
    st.write("업로드한 파일명:", uploaded_file.name)


