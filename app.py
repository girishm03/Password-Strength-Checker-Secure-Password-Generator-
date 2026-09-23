"""
Cybersecurity Password Strength Checker & Secure Password Generator.
Streamlit Web Application featuring real-time analysis, HIBP breach detection,
entropy calculations, brute-force crack time estimates, and CSPRNG generation.
"""
import streamlit as st
import pandas as pd
from core.checker import PasswordChecker, PasswordAnalysis
from core.generator import PasswordGenerator, GeneratedPassword
from core.entropy import EntropyCalculator

# Page configuration
st.set_page_config(
    page_title="CyberShield - Password Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber Dark Theme CSS
CUSTOM_CSS = """
<style>
    /* Global Styles */
    .main {
        background-color: #0b0f19;
    }
    
    /* Header typography */
    h1, h2, h3, h4 {
        color: #f3f4f6;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Cyber Card Container */
    .cyber-card {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 14px 0 rgba(0, 0, 0, 0.4);
    }
    
    /* Status Badges */
    .badge-very-strong {
        background-color: #064e3b;
        color: #34d399;
        padding: 6px 16px;
        border-radius: 9999px;
        font-weight: 700;
        border: 1px solid #059669;
        display: inline-block;
    }
    .badge-strong {
        background-color: #065f46;
        color: #6ee7b7;
        padding: 6px 16px;
        border-radius: 9999px;
        font-weight: 700;
        border: 1px solid #10b981;
        display: inline-block;
    }
    .badge-fair {
        background-color: #78350f;
        color: #fcd34d;
        padding: 6px 16px;
        border-radius: 9999px;
        font-weight: 700;
        border: 1px solid #f59e0b;
        display: inline-block;
    }
    .badge-weak {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 6px 16px;
        border-radius: 9999px;
        font-weight: 700;
        border: 1px solid #ef4444;
        display: inline-block;
    }
    .badge-very-weak {
        background-color: #450a0a;
        color: #f87171;
        padding: 6px 16px;
        border-radius: 9999px;
        font-weight: 700;
        border: 1px solid #b91c1c;
        display: inline-block;
    }
    
    /* Password display box */
    .password-display {
        font-family: 'Courier New', Courier, monospace;
        font-size: 1.3rem;
        background-color: #0f172a;
        color: #38bdf8;
        padding: 14px;
        border-radius: 8px;
        border: 1px solid #0284c7;
        word-break: break-all;
        letter-spacing: 1px;
    }
    
    /* Severity badges */
    .sev-high {
        color: #ef4444;
        font-weight: bold;
    }
    .sev-med {
        color: #f59e0b;
        font-weight: bold;
    }
    .sev-low {
        color: #38bdf8;
        font-weight: bold;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def get_badge_html(rating: str) -> str:
    slug = rating.lower().replace(" ", "-")
    return f'<span class="badge-{slug}">{rating.upper()}</span>'


# Sidebar Info & Navigation
with st.sidebar:
    st.image(
        "https://img.icons8.com/isometric/100/cyber-security.png",
        width=80,
    )
    st.title("CyberShield")
    st.caption("Password Intelligence & Generation Suite")
    st.markdown("---")

    st.markdown("### ⚙️ Quick Security Settings")
    enable_hibp = st.toggle(
        "Check HaveIBeenPwned API",
        value=True,
        help="Zero-Knowledge SHA-1 k-anonymity query to detect breached passwords. Only 5 characters of SHA-1 hash are sent.",
    )
    mask_input = st.toggle(
        "Mask Password Input",
        value=False,
        help="Hides characters on screen like a password field.",
    )

    st.markdown("---")
    st.markdown("### 🔒 Privacy Guarantee")
    st.info(
        "Passwords are analyzed locally in-memory. Full passwords or full hashes are **NEVER** sent over the network or saved."
    )


# App Header
st.title("🛡️ CyberShield Password Security Suite")
st.markdown(
    "Enterprise-grade password strength analysis, entropy benchmarking, breach validation, and cryptographically secure generation."
)

tab_check, tab_gen, tab_bulk, tab_learn = st.tabs(
    ["🔍 Strength Auditor", "⚡ Secure Generator", "📋 Bulk Auditor", "📖 Security Knowledge"]
)

# ==========================================
# TAB 1: Real-Time Strength Auditor
# ==========================================
with tab_check:
    st.subheader("Real-Time Password Strength & Vulnerability Analysis")

    input_type = "password" if mask_input else "default"
    test_password = st.text_input(
        "Enter password to evaluate:",
        value=st.session_state.get("transfer_password", "Admin@2026_Secure!"),
        type=input_type,
        key="checker_input",
        placeholder="Type or paste any password...",
    )

    if test_password:
        with st.spinner("Analyzing cryptographic entropy and checking breaches..."):
            analysis = PasswordChecker.analyze(test_password, check_breach=enable_hibp)

        # Top row: Score + Rating + Progress bar
        col_score, col_badge, col_nist = st.columns([2, 2, 2])
        with col_score:
            st.metric("Security Score", f"{analysis.score} / 100")
        with col_badge:
            st.markdown(f"**Overall Rating**<br>{get_badge_html(analysis.rating)}", unsafe_allow_html=True)
        with col_nist:
            if analysis.nist_compliant:
                st.success("✅ **NIST SP 800-63B**: Compliant")
            else:
                st.error("⚠️ **NIST SP 800-63B**: Non-Compliant")

        # Visual Score Gauge Bar
        progress_val = max(0, min(100, analysis.score)) / 100.0
        st.progress(progress_val)

        # Core Metrics Columns
        st.markdown("#### 📐 Cryptographic Metrics")
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Password Length", f"{analysis.length} chars")
        with m2:
            st.metric("Shannon Entropy", f"{analysis.entropy.entropy_bits} bits")
        with m3:
            st.metric("Character Pool Size", f"{analysis.entropy.pool_size} chars")
        with m4:
            diversity_count = sum(1 for c in [analysis.char_counts['lower'], analysis.char_counts['upper'], analysis.char_counts['digits'], analysis.char_counts['symbols']] if c > 0)
            st.metric("Character Classes", f"{diversity_count} / 4 used")

        # Breach Status Banner
        if analysis.is_breached:
            st.error(
                f"🚨 **CRITICAL VULNERABILITY**: {analysis.breach_status_message}\n\n"
                "This password was detected in public compromised database dumps. It is actively targeted in credential stuffing attacks!"
            )
        elif enable_hibp:
            st.success(f"🛡️ **Breach Status**: {analysis.breach_status_message}")

        # Estimated Time to Crack Cards
        st.markdown("#### ⏱️ Brute-Force Crack Time Projections")
        c1, c2, c3, c4 = st.columns(4)
        scenarios = list(analysis.entropy.crack_times.values())
        if len(scenarios) >= 4:
            with c1:
                st.markdown(
                    f"""<div class="cyber-card">
                    <p style="color:#9ca3af; font-size:0.85rem; margin:0;">ONLINE (RATE LIMITED)</p>
                    <h3 style="color:#38bdf8; margin:8px 0;">{scenarios[0].formatted}</h3>
                    <p style="color:#6b7280; font-size:0.75rem; margin:0;">{scenarios[0].rate_desc}</p>
                    </div>""",
                    unsafe_allow_html=True,
                )
            with c2:
                st.markdown(
                    f"""<div class="cyber-card">
                    <p style="color:#9ca3af; font-size:0.85rem; margin:0;">ONLINE (UNTHROTTLED)</p>
                    <h3 style="color:#fbbf24; margin:8px 0;">{scenarios[1].formatted}</h3>
                    <p style="color:#6b7280; font-size:0.75rem; margin:0;">{scenarios[1].rate_desc}</p>
                    </div>""",
                    unsafe_allow_html=True,
                )
            with c3:
                st.markdown(
                    f"""<div class="cyber-card">
                    <p style="color:#9ca3af; font-size:0.85rem; margin:0;">OFFLINE (RTX 4090 GPU)</p>
                    <h3 style="color:#f87171; margin:8px 0;">{scenarios[2].formatted}</h3>
                    <p style="color:#6b7280; font-size:0.75rem; margin:0;">{scenarios[2].rate_desc}</p>
                    </div>""",
                    unsafe_allow_html=True,
                )
            with c4:
                st.markdown(
                    f"""<div class="cyber-card">
                    <p style="color:#9ca3af; font-size:0.85rem; margin:0;">OFFLINE GPU CRACKING CLUSTER</p>
                    <h3 style="color:#f43f5e; margin:8px 0;">{scenarios[3].formatted}</h3>
                    <p style="color:#6b7280; font-size:0.75rem; margin:0;">{scenarios[3].rate_desc}</p>
                    </div>""",
                    unsafe_allow_html=True,
                )

        # Character Composition & Vulnerabilities Breakdown
        col_comp, col_vuln = st.columns([1, 1])

        with col_comp:
            st.markdown("#### 🔠 Character Composition Breakdown")
            comp_df = pd.DataFrame(
                {
                    "Type": ["Lowercase (a-z)", "Uppercase (A-Z)", "Digits (0-9)", "Symbols (!@#$)", "Whitespace"],
                    "Count": [
                        analysis.char_counts["lower"],
                        analysis.char_counts["upper"],
                        analysis.char_counts["digits"],
                        analysis.char_counts["symbols"],
                        analysis.char_counts["spaces"],
                    ],
                }
            )
            st.dataframe(comp_df, use_container_width=True, hide_index=True)

        with col_vuln:
            st.markdown(f"#### ⚠️ Vulnerability Findings ({len(analysis.vulnerabilities)})")
            if analysis.vulnerabilities:
                for v in analysis.vulnerabilities:
                    sev_class = "sev-high" if v.severity == "HIGH" else ("sev-med" if v.severity == "MEDIUM" else "sev-low")
                    st.markdown(
                        f"""<div style="background:#1e293b; padding:10px 14px; border-radius:8px; margin-bottom:8px; border-left:4px solid {'#ef4444' if v.severity=='HIGH' else '#f59e0b'};">
                        <span class="{sev_class}">[{v.severity}]</span> <strong>{v.title}</strong><br>
                        <span style="color:#cbd5e1; font-size:0.9rem;">{v.description}</span>
                        </div>""",
                        unsafe_allow_html=True,
                    )
            else:
                st.success("No critical pattern vulnerabilities found!")

        # Recommendations list
        st.markdown("#### 💡 Security Recommendations")
        for rec in analysis.suggestions:
            st.markdown(f"- {rec}")

    else:
        st.info("Enter a password above to begin security analysis.")


# ==========================================
# TAB 2: Secure Password Generator
# ==========================================
with tab_gen:
    st.subheader("Cryptographically Secure Password & Passphrase Generator")
    st.caption("Powered by Python's `secrets` module (Cryptographically Secure Pseudo-Random Number Generator / CSPRNG)")

    gen_mode = st.radio(
        "Select Generation Mode:",
        ["Random Complex Password", "Memorable Passphrase (Diceware/XKCD)", "Numeric PIN", "Formatted License Token"],
        horizontal=True,
    )

    generated: GeneratedPassword = None

    if gen_mode == "Random Complex Password":
        col_g1, col_g2 = st.columns([1, 1])
        with col_g1:
            pw_length = st.slider("Password Length", min_value=8, max_value=64, value=18, step=1)
            use_lower = st.checkbox("Include Lowercase letters (a-z)", value=True)
            use_upper = st.checkbox("Include Uppercase letters (A-Z)", value=True)
        with col_g2:
            use_digits = st.checkbox("Include Digits (0-9)", value=True)
            use_symbols = st.checkbox("Include Symbols (!@#$%^&*)", value=True)
            exclude_ambig = st.checkbox(
                "Exclude Ambiguous Characters (l, 1, I, O, 0, |)",
                value=True,
                help="Prevents confusing characters when reading or typing manually.",
            )

        if st.button("⚡ Generate Secure Password", type="primary", use_container_width=True):
            generated = PasswordGenerator.generate_random_password(
                length=pw_length,
                use_lower=use_lower,
                use_upper=use_upper,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=exclude_ambig,
            )
            st.session_state["last_generated"] = generated

    elif gen_mode == "Memorable Passphrase (Diceware/XKCD)":
        col_p1, col_p2 = st.columns([1, 1])
        with col_p1:
            word_count = st.slider("Number of Words", min_value=3, max_value=8, value=5, step=1)
            sep_choice = st.selectbox("Word Separator", ["- (Hyphen)", "_ (Underscore)", ". (Period)", "  (Space)"])
            sep_map = {"- (Hyphen)": "-", "_ (Underscore)": "_", ". (Period)": ".", "  (Space)": " "}
            separator = sep_map[sep_choice]
        with col_p2:
            cap_words = st.checkbox("Capitalize Each Word (Title Case)", value=True)
            add_number = st.checkbox("Append Random Digits", value=True)
            add_symbol = st.checkbox("Append Random Symbol", value=False)

        if st.button("⚡ Generate Memorable Passphrase", type="primary", use_container_width=True):
            generated = PasswordGenerator.generate_passphrase(
                num_words=word_count,
                separator=separator,
                capitalize=cap_words,
                include_number=add_number,
                include_symbol=add_symbol,
            )
            st.session_state["last_generated"] = generated

    elif gen_mode == "Numeric PIN":
        pin_len = st.slider("PIN Length", min_value=4, max_value=16, value=6, step=1)
        if st.button("⚡ Generate Secure PIN", type="primary", use_container_width=True):
            generated = PasswordGenerator.generate_pin(length=pin_len)
            st.session_state["last_generated"] = generated

    elif gen_mode == "Formatted License Token":
        c_tok1, c_tok2 = st.columns(2)
        with c_tok1:
            blocks = st.slider("Number of Blocks", min_value=2, max_value=6, value=4)
        with c_tok2:
            chars_per_block = st.slider("Characters Per Block", min_value=3, max_value=8, value=4)

        if st.button("⚡ Generate Formatted Token", type="primary", use_container_width=True):
            generated = PasswordGenerator.generate_formatted_token(
                block_count=blocks, block_length=chars_per_block
            )
            st.session_state["last_generated"] = generated

    # Render result if generated in this session
    display_gen = generated or st.session_state.get("last_generated")
    if display_gen:
        st.markdown("---")
        st.markdown("### 🔐 Generated Output")
        st.markdown(
            f'<div class="password-display">{display_gen.password}</div>',
            unsafe_allow_html=True,
        )

        col_res1, col_res2, col_res3 = st.columns([1, 1, 1])
        with col_res1:
            st.metric("Length", f"{display_gen.length} chars")
        with col_res2:
            st.metric("Entropy", f"{display_gen.entropy_bits} bits")
        with col_res3:
            st.markdown(f"**Rating**<br>{get_badge_html(display_gen.rating)}", unsafe_allow_html=True)

        if st.button("🔍 Send to Strength Auditor Tab"):
            st.session_state["transfer_password"] = display_gen.password
            st.rerun()


# ==========================================
# TAB 3: Bulk Password Auditor
# ==========================================
with tab_bulk:
    st.subheader("📋 Bulk Password Security Audit")
    st.markdown("Paste multiple passwords (one per line) to evaluate policy compliance, entropy distribution, and identify weak credentials across a dataset.")

    bulk_input = st.text_area(
        "Passwords to Audit (1 per line):",
        value="password123\nAdmin@2026\nqwerty\nCorrect-Horse-Battery-Staple-42\nK9#vL2$mP8!xR5@tW3&z\n12345678",
        height=180,
    )

    bulk_check_hibp = st.checkbox("Query HIBP API for bulk breach checks", value=False, help="May take a few seconds depending on list length")

    if st.button("🚀 Audit All Passwords", type="primary"):
        passwords = [p.strip() for p in bulk_input.splitlines() if p.strip()]
        if not passwords:
            st.warning("Please provide at least one password.")
        else:
            with st.spinner(f"Auditing {len(passwords)} passwords..."):
                records = []
                for p in passwords:
                    res = PasswordChecker.analyze(p, check_breach=bulk_check_hibp)
                    records.append(
                        {
                            "Password": p if not mask_input else "••••••••",
                            "Score": res.score,
                            "Rating": res.rating,
                            "Length": res.length,
                            "Entropy (bits)": res.entropy.entropy_bits,
                            "NIST Compliant": "✅ Yes" if res.nist_compliant else "❌ No",
                            "Breached": "🚨 YES" if res.is_breached else ("Checked Clean" if bulk_check_hibp else "Skipped"),
                            "Vulnerabilities": len(res.vulnerabilities),
                        }
                    )
            df = pd.DataFrame(records)

            st.markdown("#### 📊 Summary Statistics")
            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Total Analyzed", len(passwords))
            avg_score = round(df["Score"].mean(), 1)
            b2.metric("Average Score", f"{avg_score} / 100")
            compliant_count = sum(1 for r in records if "Yes" in r["NIST Compliant"])
            b3.metric("NIST Compliant", f"{compliant_count} / {len(passwords)}")
            weak_count = sum(1 for r in records if r["Rating"] in ["Weak", "Very Weak"])
            b4.metric("High-Risk / Weak", weak_count)

            st.dataframe(df, use_container_width=True, hide_index=True)


# ==========================================
# TAB 4: Educational Hub & Guidelines
# ==========================================
with tab_learn:
    st.subheader("📖 Password Security & NIST Guidelines")

    with st.expander("📌 What is Shannon Entropy and why does it matter?", expanded=True):
        st.markdown(
            """
            **Information Entropy** measures the unpredictability and uncertainty of a password.
            
            Mathematically, for a password of length $L$ selected uniformly from a character pool of size $R$:
            $$\\text{Entropy} = L \\times \\log_2(R) \\text{ bits}$$
            
            - **< 30 bits**: Extremely weak; crackable in milliseconds by commodity GPUs.
            - **30 - 50 bits**: Weak; susceptible to targeted brute force or dictionary attacks.
            - **50 - 70 bits**: Moderate / Fair; acceptable against throttled online guessing, but vulnerable to fast offline hash dumps.
            - **70 - 90 bits**: Strong; resistant to high-end cracking rigs.
            - **90+ bits**: Very Strong / Cryptographically sound; computationally infeasible to brute force within centuries.
            """
        )

    with st.expander("🛡️ NIST Special Publication 800-63B Standards"):
        st.markdown(
            """
            The **National Institute of Standards and Technology (NIST)** modernized password authentication guidelines:
            
            1. **Length beats complexity rules**: A longer password or multi-word passphrase is far superior to an 8-character string with arbitrary symbol requirements that users predictably mutate (e.g. `P@ssw0rd1!`).
            2. **Ban known breached passwords**: Verification against lists of compromised passwords from data breaches is mandatory.
            3. **Do not force periodic expiration**: Forcing users to change passwords every 30-90 days encourages predictable increments (e.g., `Spring2026!` -> `Summer2026!`). Only change when compromised.
            4. **No arbitrary composition rules**: Character class quotas (e.g. at least one uppercase, number, symbol) are no longer strictly recommended because they reduce natural entropy and lead to patterned substitutions.
            """
        )

    with st.expander("🔒 How Have I Been Pwned k-Anonymity Protects Your Privacy"):
        st.markdown(
            """
            When querying the **Have I Been Pwned** database, this application uses **k-Anonymity**:
            
            1. The application computes the **SHA-1** hash of your password locally.
            2. It takes only the **first 5 characters** of the hash (the *prefix*) and sends that to `https://api.pwnedpasswords.com/range/{prefix}`.
            3. The HIBP server responds with a list of all hash suffixes (~500-1000 hashes) that start with that prefix.
            4. The application compares the remaining 35 characters locally against the returned list.
            
            **Result**: Neither your password nor your full hash is ever transmitted to the server or intercepted.
            """
        )

st.markdown("---")
st.caption("🛡️ CyberShield Password Security Suite | Built with Python & Streamlit | Standard-compliant Cybersecurity Tool")
