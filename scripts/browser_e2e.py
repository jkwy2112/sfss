"""SFSS 浏览器端到端测试:真实 Chromium 驱动完整用户旅程。

覆盖历史上出问题的全部路径:登录/退出/切换账号/刷新恢复/管理台访问/门户切换。
用法: .venv/bin/python scripts/browser_e2e.py [base_url_in] [base_url_out]
"""
import sys
import time
from playwright.sync_api import sync_playwright, expect

BASE_IN = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081"
BASE_OUT = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8082"

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"PASS: {name}")
    else:
        FAILED.append(name)
        print(f"FAIL: {name} {detail}")


def login(page, base, username, password):
    page.goto(base + "/", wait_until="networkidle")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app-view:not([hidden])", timeout=8000)


def current_user_shown(page):
    return page.text_content("#current-user").strip()


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        page = ctx.new_page()

        # ---------- 旅程1: user01 登录 → 退出 → 刷新必须停在登录页 ----------
        login(page, BASE_IN, "user01", "LlSDaFzF")
        check("user01 登录后左上角显示 user01", current_user_shown(page) == "user01",
              f"实际: {current_user_shown(page)!r}")
        page.click("#logout")
        page.wait_for_selector("#login-view:not([hidden])", timeout=8000)
        page.reload(wait_until="networkidle")
        time.sleep(1.5)
        login_visible = page.is_visible("#login-view")
        check("user01 退出后刷新 → 停在登录页(不自动恢复)", login_visible,
              "登录页不可见,被自动恢复登录")

        # ---------- 旅程2: user01 登录 → 退出 → admin 登录:无任何 user01 残留 ----------
        login(page, BASE_IN, "user01", "LlSDaFzF")
        page.click("#logout")
        page.wait_for_selector("#login-view:not([hidden])", timeout=8000)
        login(page, BASE_IN, "admin", "123456")
        check("admin 登录后立即显示 admin(无 user01 残留)", current_user_shown(page) == "admin",
              f"实际: {current_user_shown(page)!r}")
        page.reload(wait_until="networkidle")
        time.sleep(1.5)
        check("admin 刷新后仍稳定显示 admin", current_user_shown(page) == "admin",
              f"实际: {current_user_shown(page)!r}")

        # ---------- 旅程3: admin 点击管理员后台,不应被踢出 ----------
        page.click("#admin-console")
        page.wait_for_selector("#admin-view:not([hidden])", timeout=8000)
        time.sleep(2)
        still_admin_view = page.is_visible("#admin-view") and not page.is_visible("#login-view")
        check("admin 打开管理后台不被踢到登录页", still_admin_view)
        check("管理后台统计卡片已渲染", page.text_content("#metric-users").strip() != "",
              "统计未加载")

        # ---------- 旅程4: admin 退出 → user01 登录 → 访问 /admin 被拒 ----------
        page.click("#logout")
        page.wait_for_selector("#login-view:not([hidden])", timeout=8000)
        login(page, BASE_IN, "user01", "LlSDaFzF")
        page.goto(BASE_IN + "/admin", wait_until="networkidle")
        time.sleep(1)
        denied = page.is_visible("#admin-view") and "无权访问" in (page.text_content("#admin-view") or "")
        check("user01 访问 /admin 显示拒绝页(非空白/非登录页)", denied)

        # ---------- 旅程5: 回到 / 应保持 user01 登录(development 会话全门户通用) ----------
        page.goto(BASE_IN + "/", wait_until="networkidle")
        time.sleep(1.5)
        check("user01 从 /admin 返回 / 保持登录", current_user_shown(page) == "user01",
              f"实际: {current_user_shown(page)!r}")

        # ---------- 旅程6: 8082 红区门户: user01 登录可用,数据为本人 ----------
        page.goto(BASE_OUT + "/red", wait_until="networkidle")
        time.sleep(1.5)
        if not page.is_visible("#login-view"):
            check("8082 /red 沿用登录态(development 会话)", current_user_shown(page) == "user01")
        else:
            login(page, BASE_OUT, "user01", "LlSDaFzF")
            check("8082 /red 登录 user01 成功", current_user_shown(page) == "user01")

        # ---------- 旅程7: 双系统同时在线(独立会话互不干扰) ----------
        page.goto(BASE_IN + "/", wait_until="networkidle")
        time.sleep(1)
        check("回 8081 仍是 user01(双系统独立)", current_user_shown(page) == "user01",
              f"实际: {current_user_shown(page)!r}")

        # ---------- 旅程8: 退出后再刷新两次,永不再恢复 ----------
        page.click("#logout")
        page.wait_for_selector("#login-view:not([hidden])", timeout=8000)
        page.reload(wait_until="networkidle"); time.sleep(1)
        page.reload(wait_until="networkidle"); time.sleep(1)
        check("退出后连续刷新两次都停在登录页", page.is_visible("#login-view"))

        browser.close()


if __name__ == "__main__":
    run()
    print()
    if FAILED:
        print(f"✗ {len(FAILED)} 项失败: {FAILED}")
        sys.exit(1)
    print(f"✓ 全部 {len(PASSED)} 项浏览器端到端测试通过")
