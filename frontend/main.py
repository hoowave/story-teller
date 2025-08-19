import streamlit as st

#사이드바 페이지 네비게이션
pages = [
    st.Page(
        "pages/upload.py",
        title="Upload",
        icon=":material/home:"
    ),
    st.Page(
        "pages/result.py",
        title="Result",
        icon=":material/chat:"
    ),
]

page = st.navigation(pages)
page.run()

# 사이드바 하단 캡션
st.sidebar.caption(
    "© 스토리텔러"
)


# if __name__ == "__main__":
#     print("Streamlit server is starting...")