import datetime

# --- 1. Define Security Policies (Controls) ---
# These functions represent specific SOC 2 controls or policies.
# A return value of False indicates non-compliance (a "failed test").
def policy_password_complexity(password: str) -> bool:
    """
    Policy: Passwords must be at least 8 characters, contain uppercase, lowercase, and a digit.
    """
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    return True

def policy_mfa_enabled_for_admins(user_role: str, mfa_status: bool) -> bool:
    """
    Policy: Admin users must have Multi-Factor Authentication (MFA) enabled.
    """
    if user_role == "admin" and not mfa_status:
        return False
    return True

# --- 2. Simulate System Data for Review ---
# In a real scenario, this data would come from your user database,
# configuration management, or other system sources.
simulated_user_data = [
    {"username": "alice", "password_string_for_test": "SecureP@ss1", "role": "user", "mfa_enabled": False},
    {"username": "bob", "password_string_for_test": "AdminP@ssW0rd", "role": "admin", "mfa_enabled": True},
    {"username": "charlie", "password_string_for_test": "short", "role": "user", "mfa_enabled": False}, # Fails password complexity
    {"username": "david", "password_string_for_test": "StrongP@ss2", "role": "admin", "mfa_enabled": False}, # Fails MFA for admin
]

# --- 3. Conduct the SOC 2 Policy Review Process ---
def conduct_soc2_review(data_to_evaluate: list):
    """
    Simulates a SOC 2 policy review, treating non-compliant findings
    as "failed tests" that lead to continuous improvement actions.
    """
    print(f"--- SOC 2 Policy Review Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
    improvement_opportunities = [] # This list collects all "failed tests" for action.

    for user in data_to_evaluate:
        username = user["username"]
        print(f"\nReviewing user: {username}")

        # Test 1: Password Complexity Policy
        # This simulates checking a user's password against the defined policy.
        is_password_compliant = policy_password_complexity(user.get("password_string_for_test", ""))
        if not is_password_compliant:
            # --- ARTICLE CONCEPT: This is a "failed test" ---
            # Instead of just marking it as failed, we identify it as an opportunity
            # for continuous improvement and suggest a concrete action.
            improvement_opportunities.append({
                "policy": "Password Complexity",
                "item": f"User '{username}'",
                "finding": "Password does not meet current complexity requirements.",
                "suggested_action": "Require user to update password; implement system-level enforcement for new/reset passwords.",
                "severity": "High"
            })
            print(f"  [FAIL] Password Complexity: Non-compliant. (Identified as improvement opportunity)")
        else:
            print(f"  [PASS] Password Complexity: Compliant.")

        # Test 2: MFA for Admin Users Policy
        is_mfa_compliant = policy_mfa_enabled_for_admins(user["role"], user["mfa_enabled"])
        if not is_mfa_compliant:
            # --- ARTICLE CONCEPT: Another "failed test" ---
            improvement_opportunities.append({
                "policy": "MFA for Admin Users",
                "item": f"User '{username}'",
                "finding": "Admin user does not have MFA enabled.",
                "suggested_action": "Mandate MFA for all admin roles; provide clear setup instructions and support.",
                "severity": "Critical"
            })
            print(f"  [FAIL] MFA for Admin Users: Non-compliant. (Identified as improvement opportunity)")
        else:
            print(f"  [PASS] MFA for Admin Users: Compliant.")

    print("\n--- Review Summary: Continuous Improvement Opportunities ---")
    if not improvement_opportunities:
        print("All policies are compliant. No improvement opportunities identified in this review cycle.")
    else:
        print(f"Identified {len(improvement_opportunities)} areas for improvement (failed tests):")
        for i, opp in enumerate(improvement_opportunities):
            print(f"\n{i+1}. Policy: {opp['policy']}")
            print(f"   Item: {opp['item']}")
            print(f"   Finding: {opp['finding']}")
            print(f"   Suggested Action: {opp['suggested_action']}") # Key for continuous improvement
            print(f"   Severity: {opp['severity']}")
            print("   -> This finding is a valuable learning point to enhance our security posture.")

    print("\n--- SOC 2 Policy Review Completed ---")

# --- 4. Execute the Review ---
if __name__ == "__main__":
    conduct_soc2_review(simulated_user_data)
