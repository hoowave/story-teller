import streamlit as st
import json
import pandas as pd
import plotly.graph_objects as go
import altair as alt

st.set_page_config(page_title="보안 로그 클러스터링 분석", layout="wide")
st.title("🔎로그 분석 결과")
# 세션 스테이트에서 JSON 불러오기
json1 = st.session_state.get("json1", {})
json2 = st.session_state.get("json2", {})

if json1 and json2:
    result1 = json1.get("analysis_result",{})
    result2 = json2.get("LLM 응답",[{}])[0]

    # 탭 구성
    tabs = st.tabs(["공격 시나리오 & 권고사항","종합 위험도", "상세 분석 결과"])

    # 탭 1: 공격 시나리오 & 권고사항
    # 탭 1: 공격 시나리오 & 권고사항
    with tabs[0]:
        st.header("⚠️ 공격 시나리오 & 권고사항")

        col1, col2 = st.columns(2)
        # 공격 시나리오
        with col1:
            st.subheader("공격 시나리오")
            scenario_text = result2.get("현재상황", "시나리오 없음")
            scenario_lines = scenario_text.split(". ")
            for line in scenario_lines:
                if line.strip():
                    st.warning(line.strip())

            # 심각도 / 위험도 점수 / 영향 범위
            with st.expander("📖 시나리오 세부정보"):
                # 데이터 가져오기
                severity = result2.get("심각도", "정보 없음")
                risk_score = result2.get("위험도점수", None)
                impact_scope = result2.get("영향범위", [])
                col3, col4 = st.columns(2)
                with col3:
                    # 기존 metric 표시
                    st.metric(label="심각도", value=severity)

                    # 위험도 점수 차트
                    if risk_score is not None:
                        fig = go.Figure(go.Indicator(
                            mode="gauge+number",
                            value=risk_score,
                            title={'text': "위험도 점수"},
                            gauge={
                                'axis': {'range': [0, 10]},
                                'bar': {'color': "#6B1BFF"},
                                'steps': [
                                    {'range': [0, 3], 'color': "#2ECC71"},   # Low
                                    {'range': [3, 7], 'color': "#FFDC00"},  # Medium
                                    {'range': [7, 10], 'color': "#FF4136"}  # High
                                ],
                                'threshold': {
                                    'line': {'color': "red", 'width': 4},
                                    'thickness': 0.75,
                                    'value': risk_score
                                }
                            }
                        ))
                        fig.update_layout(height=300)
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.write("위험도 점수 정보 없음")
                with col4:
                    # 영향 범위 표시
                    if impact_scope:
                        st.write("영향 범위:")
                        for item in impact_scope:
                            st.write(f"- {item}")

                # 근거(event) 테이블 표시
                st.subheader("근거(Event)")
                evidence_list = result2.get("근거", [])
                if evidence_list:
                    df_evidence = pd.DataFrame([
                        {
                            "시간": ev.get("시간", ""),
                            "요약": ev.get("요약", ""),
                            "cluster_id": ev.get("참조", {}).get("cluster_id", ""),
                            "event_id": ev.get("참조", {}).get("event_id", "")
                        }
                        for ev in evidence_list
                    ])
                    st.dataframe(df_evidence, use_container_width=True)
                else:
                    st.write("근거 정보 없음")

        # 권고사항
        with col2:
            st.subheader("권고사항")
            recs = result2.get("권장대응", [])
            for r in recs:
                st.info(r)


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
        #priority_level_desc = "위 지표들을 종합하여 사건 대응 우선순위를 표시합니다. HIGH, MEDIUM, LOW 등으로 나타납니다."
        

        col1.metric("시간 집중도", metrics.get("time_concentration", 0), help=time_concentration_desc)
        col2.metric("IP 다각화", metrics.get("ip_diversification", 0), help=ip_diversification_desc)
        col3.metric("사용자 이상행동", metrics.get("user_anomaly", 0), help=user_anomaly_desc)
        col4.metric("파일 민감도", metrics.get("file_sensitivity", 0), help=file_sensitivity_desc)
        #col5.metric("우선순위", result1.get("priority_level", "").upper(), help=priority_level_desc)

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

        bars = alt.Chart(score_chart_df).mark_bar(size=40).encode(
            x=alt.X("지표", sort=["시간 집중도", "IP 다각화", "사용자 이상행동", "파일 민감도"]),
            y="값",
            color=alt.Color("지표", scale=alt.Scale(scheme="set2")),
            tooltip=["지표", "값"]
        )

        text = bars.mark_text(
            align = "center",
            baseline = "middle",
            dy = -5
        ).encode(
            text=alt.Text("값:Q", format=".2f")
        )

        chart = (bars + text).configure_axis(labelAngle=0)
        st.altair_chart(chart, use_container_width=True)



    # 탭 3: 상세 분석 결과 (1행 3열로 압축)
    with tabs[2]: 
        st.header("🔎 상세 분석 결과")
        da = result1.get("detailed_analysis", {})

        # 시간 분석
        with st.expander("⏱ 시간 분석"):
            t = da.get("time_analysis", {})
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("버스트 공격 탐지", "✅" if t.get("burst_attack_detected") else "❌")
                st.metric("총 공격 지속시간(초)", t.get("total_duration"))

                st.metric("버스트 강도", f"{t.get('burst_intensity', 0):.2f}")
                st.metric("이벤트 밀도", f"{round(t.get('event_density', 0), 3):.3f}","(이벤트/초)")
            with col2: 
                fig1 = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=t.get("burst_intensity", 0),
                    title={"text": "버스트 강도"},
                    gauge={'axis': {'range': [0, 1]}}
                ))
                st.plotly_chart(fig1, use_container_width=True)
            with col3:
                fig2 = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=t.get("event_density", 0),
                    title={'text': "이벤트 밀도"},
                    gauge={'axis': {'range': [0, 0.1]}}
                ))
                st.plotly_chart(fig2, use_container_width=True)

        # IP 분석
        with st.expander("🌐 IP 분석"):
            ip = da.get("ip_analysis", {})
            col1, col2 = st.columns(2)
            with col1:
                st.metric("외부→내부 이동 ", f"{ip.get("external_to_internal")}회")
                st.metric("내부→내부 이동 ", f"{ip.get("internal_to_internal")}회")
                st.metric("측면 이동 감지", "✅" if ip.get("lateral_movement_detected") else "❌")
                st.metric("네트워크 침투 깊이", f"{ip.get('network_penetration_depth')} 단계")
            with col2:
                labels = ["External→Internal", "Internal→Internal"]
                values = [ip.get("external_to_internal", 0), ip.get("internal_to_internal", 0)]
                pie_chart = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
                st.plotly_chart(pie_chart, use_container_width=True)


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
                if file_analysis:
                    high_risk_records = []
                    for file_info in file_analysis:
                        for f in file_info["high_risk_files"]:
                            high_risk_records.append({
                                "파일": f["file"],
                                "사용자": f["user"],
                                "접근 시각": f["timestamp"],
                                "민감도": f["sensitivity"],
                                "파일 유출 위험 점수": file_info["exfiltration_risk_score"]
                            })
                    df_file = pd.DataFrame(high_risk_records)
                    st.dataframe(df_file, use_container_width=True)
                else:
                    st.info("분석 JSON 파일을 찾을 수 없습니다.")
else: st.warning("분석할 로그파일을 먼저 업로드해 주세요")
