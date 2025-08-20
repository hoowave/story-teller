import streamlit as st
import pandas as pd
import altair as alt
import pydeck as pdk
import json

st.title("보안 사고 분석 대시보드")

# 세션 상태에서 업로드된 데이터 가져오기
if 'log_data' not in st.session_state:
    st.warning("분석할 데이터가 없습니다. 먼저 파일을 업로드하세요.")
else:
    data = st.session_state['log_data']
    df = pd.json_normalize(data)

    tabs = st.tabs(["공격 타임라인", "공격자 특성", "피해자산 및 영향", "권장대응"])

    # 공격 타임라인 탭
    with tabs[0]:
        st.header("공격 진행 타임라인")
        timeline_chart = alt.Chart(df).mark_bar().encode(
            x='timestamp:T',
            y='attack_stage:N',
            color='severity:N',
            tooltip=['timestamp', 'attack_stage', 'description']
        )
        st.altair_chart(timeline_chart, use_container_width=True)
        st.subheader("공격 시나리오")
        st.markdown("""
            정보 수집

            공격자는 로그인 폼에 임의 값 입력 후, 오류 메시지나 응답 패턴을 확인.

            예: "아이디가 존재하지 않습니다" 같은 메시지로 테이블 구조 유추.

            취약점 확인

            입력 필드에 특수문자 ' 또는 ", -- 등을 삽입하여 쿼리 오류 발생 여부 확인.

            에러 메시지에서 DBMS 종류(MySQL, MSSQL, Oracle 등) 노출 가능.

            우회 시도

            비밀번호 검증 구문을 우회하는 조건 삽입.

            예: OR '1'='1 같은 논리 참 조건을 사용.

            정상 사용자 계정으로 인증을 우회.

            데이터 추출

            UNION 기반 기법으로 다른 테이블의 컬럼 확인.

            DB 스키마 정보 추출 후, 민감 데이터(계정, 비밀번호 해시, 개인정보) 조회 시도.

            권한 상승 및 내부 장악

            DBMS 계정 권한이 높으면 시스템 명령 실행 가능.

            웹서버 또는 OS 수준 접근으로 확장될 수 있음
            """)


    
    # 공격자 특성 탭
    with tabs[1]:
        st.subheader("공격자 특성")
        st.dataframe(df[['attacker_ip','country','attack_type']].drop_duplicates())

        st.subheader("공격자 위치 지도")
        df_map = df.dropna(subset=['latitude','longitude'])
        if not df_map.empty:
         st.pydeck_chart(pdk.Deck(
            initial_view_state=pdk.ViewState(
                latitude=df_map['latitude'].mean(),
                longitude=df_map['longitude'].mean(),
                zoom=1
            ),
            layers=[
                pdk.Layer(
                    "ScatterplotLayer",
                    data=df_map,
                    get_position='[longitude, latitude]',
                    get_color='[255, 0, 0]',
                    get_radius=100000,
                )
            ]
        ))
        else:
            st.info("위치 정보가 없습니다.")

   
    # 피해 자산 및 영향 탭
    with tabs[2]:
        st.header("피해 자산 및 영향")
        st.dataframe(df[['target_asset','impact']].drop_duplicates())

    # 탐지 & 대응 포인트 탭
    with tabs[3]:
        st.header("탐지 & 대응 포인트")
        st.metric("총 공격 건수", len(df))
        st.metric("Unique IP 수", df['attacker_ip'].nunique())
        st.write("권고 대응 조치:")
        st.markdown("""
        - 의심 IP 차단
        - WAF 룰 강화
        - MFA 적용
        - 로그 모니터링 강화
        """)

