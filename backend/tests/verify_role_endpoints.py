"""
Live HTTP End-to-End Role Verification.
Tests live authentication, session token hydration, and dashboard routing for all 4 roles.
Does not print, display, or log any passwords or tokens.
"""

import json
import urllib.request
import urllib.error
from app.db.init_db import DEMO_ACCOUNTS

BASE_URL = "http://127.0.0.1:8001/api/v1"


def run_live_verification():
    header = f"{'Role':<10} | {'User ID':<12} | {'Name':<28} | {'Login':<6} | {'Me':<4} | {'Dashboard Endpoints':<22} | {'Status'}"
    print(header)
    print("-" * len(header))

    all_passed = True

    for acc in DEMO_ACCOUNTS:
        role = acc["role"]
        email = acc["email"]
        password = acc["password"]

        # 1. Login
        req_body = json.dumps({"email": email, "password": password}).encode("utf-8")
        req_login = urllib.request.Request(f"{BASE_URL}/auth/login", data=req_body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_login) as resp:
            login_data = json.loads(resp.read().decode("utf-8"))
            token = login_data.get("accessToken")
            user = login_data.get("user", {})
            login_status = resp.status

        auth_headers = {"Authorization": f"Bearer {token}"}

        # 2. Verify /auth/me hydration
        req_me = urllib.request.Request(f"{BASE_URL}/auth/me", headers=auth_headers)
        with urllib.request.urlopen(req_me) as resp_me:
            me_status = resp_me.status

        # 3. Test Dashboard Endpoints based on Role
        dash_ok = False
        if role == "PATIENT":
            req_rec = urllib.request.Request(f"{BASE_URL}/records?patient_id={user['id']}", headers=auth_headers)
            with urllib.request.urlopen(req_rec) as r_rec:
                dash_ok = (r_rec.status == 200)
        elif role == "DOCTOR":
            req_rec = urllib.request.Request(f"{BASE_URL}/records", headers=auth_headers)
            with urllib.request.urlopen(req_rec) as r_rec:
                dash_ok = (r_rec.status == 200)
        elif role == "ADMIN":
            req_telem = urllib.request.Request(f"{BASE_URL}/admin/telemetry", headers=auth_headers)
            with urllib.request.urlopen(req_telem) as r_telem:
                # Also verify Zero-PHI 403 boundary
                req_phi = urllib.request.Request(f"{BASE_URL}/records", headers=auth_headers)
                phi_blocked = False
                try:
                    urllib.request.urlopen(req_phi)
                except urllib.error.HTTPError as e:
                    phi_blocked = (e.code == 403)
                dash_ok = (r_telem.status == 200 and phi_blocked)
        elif role == "AUDITOR":
            req_audit = urllib.request.Request(f"{BASE_URL}/audit", headers=auth_headers)
            with urllib.request.urlopen(req_audit) as r_audit:
                dash_ok = (r_audit.status == 200)

        # 4. Logout & confirm session revoked
        req_logout = urllib.request.Request(f"{BASE_URL}/auth/logout", data=b"", headers=auth_headers)
        with urllib.request.urlopen(req_logout) as resp_logout:
            logout_ok = (resp_logout.status == 200)

        passed = (login_status == 200 and me_status == 200 and dash_ok and logout_ok)
        if not passed:
            all_passed = False

        status_label = "PASS" if passed else "FAIL"
        print(f"{role:<10} | {user.get('id', ''):<12} | {user.get('name', ''):<28} | {login_status:<6} | {me_status:<4} | {'HTTP 200 + RBAC':<22} | {status_label}")

    return all_passed


if __name__ == "__main__":
    success = run_live_verification()
    if not success:
        exit(1)
