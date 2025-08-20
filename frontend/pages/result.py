import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go
import altair as alt

st.set_page_config(page_title="보안 로그 클러스터링 분석", layout="wide")
st.title("로그 분석 결과")

# JSON 업로드 (test용)
#uploaded_file = st.file_uploader("분석 JSON 파일 업로드", type="json", accept_multiple_files=False)

# 세션 스테이트에서 JSON 불러오기
json1 = st.session_state.get("json1", {})
json2 = st.session_state.get("json2", {})

if json1 and json2:
    result1 = json1.get("analysis_result",{})
    result2 = json2.get("LLM 응답",[{}])[0]

# 테스트용 코드입니다 무시하세요
# if uploaded_file:
#     data = json.load(uploaded_file)
#     result = data.get("analysis_result", {})

    # 탭 구성
    tabs = st.tabs(["공격 시나리오 & 권고사항","종합 위험도", "상세 분석 결과"])

    # 탭 1: 공격 시나리오 & 권고사항
    with tabs[0]:
        st.header("⚠️ 공격 시나리오 & 권고사항")
        st.subheader("공격 시나리오")
        st.warning(result2.get("현재상황", "시나리오 없음"))

        st.subheader("권고사항")
        recs = result2.get("권장대응", [])
        for r in recs:
            st.markdown(f"- [ ] {r}")

    # 탭 2: 종합 위험도
    with tabs[1]:
        st.header("📊 종합 위험도")
        metrics = result1.get("metrics", {})
        risk_score = metrics.get("overall_risk_score", 0)

        # 게이지 차트
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score*100,
            title={'text': "종합 위험도"},
            gauge={'axis': {'range': [0, 100]},
                   'bar': {'color': "red"},
                   'steps': [
                       {'range': [0, 50], 'color': "lightgreen"},
                       {'range': [50, 75], 'color': "yellow"},
                       {'range': [75, 100], 'color': "red"}]}))
        st.plotly_chart(fig, use_container_width=True)

        # 핵심 지표 (카드 + 막대그래프 색상 일치)
        st.subheader("핵심 지표")
        col1, col2, col3, col4, col5 = st.columns(5)
        time_concentration_desc = "특정 공격이나 이상행동이 짧은 시간 내에 집중적으로 발생했는지 나타냅니다. 값이 높을수록 단기 공격 가능성이 높습니다."
        ip_diversification_desc = "공격이나 접속이 여러 IP에서 발생했는지 평가합니다. 값이 높으면 분산 공격 가능성을 시사합니다."
        user_anomaly_desc = "정상 사용자 패턴과 비교했을 때 이상행동 발생 정도입니다. 값이 높을수록 비정상적 접근 위험이 증가합니다."
        file_sensitivity_desc = "접근된 파일이나 데이터의 민감도입니다. 값이 높으면 중요/기밀 자료에 접근했음을 의미합니다."
        priority_level_desc = "위 지표들을 종합하여 사건 대응 우선순위를 표시합니다. HIGH, MEDIUM, LOW 등으로 나타납니다."
        
        col1.metric("시간 집중도", metrics.get("time_concentration", 0), help=time_concentration_desc)
        col2.metric("IP 다각화", metrics.get("ip_diversification", 0), help=ip_diversification_desc)
        col3.metric("사용자 이상행동", metrics.get("user_anomaly", 0), help=user_anomaly_desc)
        col4.metric("파일 민감도", metrics.get("file_sensitivity", 0), help=file_sensitivity_desc)
        col5.metric("우선순위", result1.get("priority_level", "").upper(), help=priority_level_desc)

        # 세부 지표 막대 차트
        st.subheader("세부 지표 시각화")

        # 원하는 순서 지정
        ordered_metrics = [
            ("시간 집중도", metrics.get("time_concentration", 0)),
            ("IP 다각화", metrics.get("ip_diversification", 0)),
            ("사용자 이상행동", metrics.get("user_anomaly", 0)),
            ("파일 민감도", metrics.get("file_sensitivity", 0))
        ]

        score_chart_df = pd.DataFrame(ordered_metrics, columns=["지표", "값"])

        chart = alt.Chart(score_chart_df).mark_bar().encode(
            x=alt.X("지표", sort=["시간 집중도", "IP 다각화", "사용자 이상행동", "파일 민감도"]),
            y="값",
            color=alt.Color("지표", scale=alt.Scale(scheme="set2")),
            tooltip=["지표", "값"]
        )
        st.altair_chart(chart, use_container_width=True)



    # 탭 3: 상세 분석 결과 (1행 3열로 압축)
    with tabs[2]: 
        st.header("🔎 상세 분석 결과")
        da = result1.get("detailed_analysis", {})

        # 시간 분석
        with st.expander("⏱ 시간 분석"):
            t = da.get("time_analysis", {})
            st.metric("버스트 공격 탐지", "✅" if t.get("burst_attack_detected") else "❌")
            st.metric("총 공격 지속시간(초)", t.get("total_duration"))
            st.metric("버스트 강도", t.get("burst_intensity"))
            st.metric("이벤트 밀도", round(t.get("event_density", 0), 3),"(이벤트/초)")


        # IP 분석
        with st.expander("🌐 IP 분석"):
            ip = da.get("ip_analysis", {})
            st.metric("외부→내부 이동 ", f"{ip.get("external_to_internal")}회")
            st.metric("내부→내부 이동 ", f"{ip.get("internal_to_internal")}회")
            st.metric("측면 이동 감지", "✅" if ip.get("lateral_movement_detected") else "❌")
            st.metric("네트워크 침투 깊이", f"{ip.get('network_penetration_depth')} 단계")


        # 사용자 분석
        with st.expander("👤 사용자 및 파일 분석"):
            user = da.get("user_analysis", {})
            st.metric("권한 확장 감지", "✅" if user.get("escalation_detected") else "❌")
            st.metric("위험 레벨", user.get("risk_level"))

            with st.expander("세부 활동 내역 보기"):
                st.subheader("권한 상승 지표")
                for indicator in user['escalation_indicators']:
                    st.markdown(f"- **{indicator}**")

                st.subheader("민감 파일 접근 내역")
                file_analysis = da.get("file_analysis", [])
                for file_info in file_analysis:
                    for high_risk_file in file_info['high_risk_files']:
                        st.markdown(f"""
                        - **파일**: `{high_risk_file['file']}`
                        - **사용자**: `{high_risk_file['user']}`
                        - **접근 시각**: `{high_risk_file['timestamp']}`
                        - **민감도**: {high_risk_file['sensitivity']}
                        """)
                        st.markdown(f"**파일 유출 위험 점수**: {file_info['exfiltration_risk_score']}")

else:
    st.info("먼저 분석 JSON 파일을 업로드하세요.")
