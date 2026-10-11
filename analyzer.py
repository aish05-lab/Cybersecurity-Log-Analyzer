
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "ip", "username", "event", "details"
]


def load_logs(file):
    """Read and clean a cybersecurity CSV log file."""

    df = pd.read_csv(file)
    df.columns = [str(c).strip().lower() for c in df.columns]

    missing = set(REQUIRED_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(
            "Missing columns: " + ", ".join(sorted(missing))
        )

    for column in ["ip", "username", "event", "details"]:
        df[column] = df[column].fillna("").astype(str).str.strip()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    df = df.dropna(subset=["timestamp"])
    df = df[
        (df["ip"] != "") &
        (df["username"] != "") &
        (df["event"] != "")
    ].copy()

    df["event"] = (
        df["event"].str.upper().str.replace(" ", "_")
    )

    return df.sort_values("timestamp").reset_index(drop=True)


def analyze_logs(df, threshold=5, window_minutes=10):
    """Generate statistics and rule-based security alerts."""

    df = df.copy()

    df["is_failed"] = df["event"].isin([
        "LOGIN_FAILED", "FAILED_LOGIN",
        "LOGIN_FAILURE", "AUTH_FAILURE"
    ])

    df["is_success"] = df["event"].isin([
        "LOGIN_SUCCESS", "SUCCESSFUL_LOGIN", "AUTH_SUCCESS"
    ])

    failed = df[df["is_failed"]].copy()
    successful = df[df["is_success"]].copy()

    # Count events for each IP address
    failed_by_ip = failed.groupby("ip").size().rename(
        "failed_attempts"
    )
    success_by_ip = successful.groupby("ip").size().rename(
        "successful_logins"
    )

    ip_summary = pd.concat(
        [failed_by_ip, success_by_ip], axis=1
    ).fillna(0).astype(int).reset_index()

    ip_summary = ip_summary.sort_values(
        "failed_attempts", ascending=False
    )

    alerts = []

    # Rule 1: repeated failures within the selected time window
    for ip, group in failed.groupby("ip"):
        times = group["timestamp"].sort_values().tolist()
        left = 0

        for right, current_time in enumerate(times):
            while (
                times[left]
                < current_time - pd.Timedelta(minutes=window_minutes)
            ):
                left += 1

            count = right - left + 1

            if count >= threshold:
                alerts.append({
                    "timestamp": current_time,
                    "ip": ip,
                    "alert_type": "Possible Brute-Force Attack",
                    "severity": "HIGH",
                    "description": (
                        f"{count} failed attempts within "
                        f"{window_minutes} minutes"
                    )
                })
                break

    # Rule 2: successful login after 3 or more recent failures
    for _, success in successful.iterrows():
        start = success["timestamp"] - pd.Timedelta(minutes=30)

        recent = failed[
            (failed["ip"] == success["ip"]) &
            (failed["timestamp"] >= start) &
            (failed["timestamp"] < success["timestamp"])
        ]

        if len(recent) >= 3:
            alerts.append({
                "timestamp": success["timestamp"],
                "ip": success["ip"],
                "alert_type": "Success After Repeated Failures",
                "severity": "MEDIUM",
                "description": (
                    f"{len(recent)} failed attempts before success "
                    "within 30 minutes"
                )
            })

    alert_columns = [
        "timestamp", "ip", "alert_type", "severity", "description"
    ]
    alert_df = pd.DataFrame(alerts, columns=alert_columns)

    if not alert_df.empty:
        alert_df = alert_df.drop_duplicates(
            subset=["ip", "alert_type"]
        ).sort_values("timestamp").reset_index(drop=True)

    timeline = (
        df.assign(date=df["timestamp"].dt.strftime("%Y-%m-%d"))
        .groupby(["date", "event"])
        .size()
        .rename("count")
        .reset_index()
    )

    return {
        "total_events": len(df),
        "failed_count": int(df["is_failed"].sum()),
        "success_count": int(df["is_success"].sum()),
        "unique_ips": int(df["ip"].nunique()),
        "ip_summary": ip_summary,
        "alerts": alert_df,
        "timeline": timeline,
        "cleaned_logs": df
    }
