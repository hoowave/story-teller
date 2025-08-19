import streamlit as st

st.title("로그 분석 결과입니다")

# 탭 구성
tabs = st.tabs(["시나리오", "로그", "그래프", "상황", "권장대응", "PDF"])

# 시나리오 탭
with tabs[0]:
    with st.container():
        st.subheader("시나리오")

# 로그 탭
with tabs[1]:
    with st.container():
        st.subheader("로그")

# 그래프 탭
with tabs[2]:
    with st.container():
        st.subheader("그래프")

# 상황 탭
with tabs[3]:
    with st.container():
        st.subheader("상황")

# 권장대응 탭
with tabs[4]:
    with st.container():
        st.subheader("권장대응")

# PDF 탭
with tabs[5]:
    with st.container():
        st.subheader("PDF")