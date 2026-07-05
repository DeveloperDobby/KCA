from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

import requests

DEFAULT_POSTS_API_TEMPLATE = (
    "https://pf.kakao.com/rocket-web/web/profiles/{profile_id}/posts?includePinnedPost=true"
)
DEFAULT_CHANNEL_URL_TEMPLATE = "https://pf.kakao.com/{profile_id}/posts"
DEFAULT_TIMEZONE = "Asia/Seoul"
DEFAULT_CHECK_INTERVAL_SECONDS = 60
# Workflow timeout is 359 minutes. Default loop duration stays slightly under it for clean shutdown.
DEFAULT_RUN_DURATION_SECONDS = 21_480
DEFAULT_ERROR_ALERT_COOLDOWN_SECONDS = 1_800
MAX_SEEN_IDS_PER_CHANNEL = 1_000

LEVEL_ICON = {
    "success": "✅",
    "info": "ℹ️",
    "warning": "⚠️",
    "error": "🚨",
    "new": "📢",
}


@dataclass(frozen=True)
class ChannelTarget:
    profile_id: str
    api_url: str
    channel_url: str
    target_key: str


@dataclass(frozen=True)
class KakaoPost:
    post_id: str
    url: str
    title: str
    body: str = ""
    published_at: str = ""
    image_url: str = ""
    raw_published_at: int | None = None
    raw_updated_at: int | None = None
    raw_created_at: int | None = None


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        log(f"Invalid integer for {name}. Falling back to {default}.")
        return default
    return max(minimum, value)


def now_text(tz_name: str = DEFAULT_TIMEZONE) -> str:
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S %Z")


def timestamp_ms_to_text(value: Any, tz_name: str = DEFAULT_TIMEZONE) -> str:
    if value in (None, ""):
        return ""
    try:
        timestamp = int(value) / 1000
    except (TypeError, ValueError):
        return ""
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc
    return datetime.fromtimestamp(timestamp, tz).strftime("%Y-%m-%d %H:%M:%S %Z")


def log(message: str) -> None:
    print(f"[{now_text()}] {message}", flush=True)


def clean_text(value: str, *, max_len: int = 900) -> str:
    text = re.sub(r"[ \t\r\f\v]+", " ", value or "")
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > max_len:
        return text[: max_len - 1].rstrip() + "…"
    return text


def raw_discord_mention() -> str:
    """Read the mention target from Secrets.

    Preferred Secret: DISCORD_MENTION
      - 123456789012345678  -> user mention <@123456789012345678>
      - everyone / @everyone -> server-wide @everyone mention
      - here / @here         -> online-members @here mention
      - <@123...>, <@&123...>, @everyone, @here are also accepted as-is.

    Backward compatibility: if DISCORD_MENTION is empty, DISCORD_USER_ID is used.
    """
    return (
        os.environ.get("DISCORD_MENTION", "").strip()
        or os.environ.get("DISCORD_USER_ID", "").strip()
    )


def normalize_discord_mention(raw: str) -> tuple[str, dict[str, Any]]:
    value = (raw or "").strip()
    if not value:
        return "", {"parse": []}

    lowered = value.lower()
    if lowered in {"everyone", "@everyone"}:
        return "@everyone ", {"parse": ["everyone"]}
    if lowered in {"here", "@here"}:
        return "@here ", {"parse": ["everyone"]}

    user_match = re.fullmatch(r"<@!?(\d+)>", value) or re.fullmatch(r"(\d+)", value)
    if user_match:
        user_id = user_match.group(1)
        return f"<@{user_id}> ", {"parse": [], "users": [user_id]}

    role_match = re.fullmatch(r"<@&(\d+)>", value)
    if role_match:
        role_id = role_match.group(1)
        return f"<@&{role_id}> ", {"parse": [], "roles": [role_id]}

    # Unknown values are rendered as plain text but mention parsing is disabled
    # so a malformed Secret cannot unexpectedly ping people.
    log("Invalid DISCORD_MENTION/DISCORD_USER_ID value. Mention will be sent as plain text without ping.")
    return f"{value} ", {"parse": []}


def discord_mention() -> str:
    mention, _ = normalize_discord_mention(raw_discord_mention())
    return mention


def allowed_mentions() -> dict[str, Any]:
    _, mentions = normalize_discord_mention(raw_discord_mention())
    return mentions


def target_key(profile_id: str) -> str:
    """Mask profile ids in logs without storing or committing target ids."""
    return hashlib.sha256(profile_id.encode("utf-8")).hexdigest()


def normalize_profile_id(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""

    # Secret에는 plain profile id, 채널 URL, rocket-web API URL 중 아무 형식이나 넣을 수 있습니다.
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        path_parts = [part for part in parsed.path.split("/") if part]
        if "profiles" in path_parts:
            index = path_parts.index("profiles")
            if index + 1 < len(path_parts):
                value = path_parts[index + 1]
        elif path_parts:
            value = path_parts[0]

    value = value.strip().rstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_\-+.]+", value):
        raise ValueError("Invalid Kakao profile id format in KAKAO_PROFILE_IDS secret.")
    return value


def split_profile_ids(raw: str) -> list[str]:
    candidates = re.split(r"[\s,;]+", raw or "")
    ids: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate.strip():
            continue
        profile_id = normalize_profile_id(candidate)
        if profile_id and profile_id not in seen:
            ids.append(profile_id)
            seen.add(profile_id)
    return ids


def load_profile_ids_from_env() -> list[str]:
    raw = os.environ.get("KAKAO_PROFILE_IDS", "").strip()
    if not raw:
        raw = os.environ.get("KAKAO_PROFILE_ID", "").strip()
    return split_profile_ids(raw)


def template_value(template: str, profile_id: str) -> str:
    return template.format(profile_id=quote(profile_id, safe=""))


def build_targets(profile_ids: Iterable[str]) -> list[ChannelTarget]:
    api_template = os.environ.get("KAKAO_POSTS_API_TEMPLATE", DEFAULT_POSTS_API_TEMPLATE).strip()
    channel_template = os.environ.get("KAKAO_CHANNEL_URL_TEMPLATE", DEFAULT_CHANNEL_URL_TEMPLATE).strip()

    targets: list[ChannelTarget] = []
    for profile_id in profile_ids:
        targets.append(
            ChannelTarget(
                profile_id=profile_id,
                api_url=template_value(api_template, profile_id),
                channel_url=template_value(channel_template, profile_id),
                target_key=target_key(profile_id),
            )
        )
    return targets


def request_headers(profile_id: str) -> dict[str, str]:
    referer = template_value(DEFAULT_CHANNEL_URL_TEMPLATE, profile_id)
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Referer": referer,
    }


def fetch_json(target: ChannelTarget) -> dict[str, Any]:
    masked = target.target_key[:12]
    try:
        response = requests.get(target.api_url, headers=request_headers(target.profile_id), timeout=25)
        response.raise_for_status()
    except requests.RequestException as error:
        status = getattr(getattr(error, "response", None), "status_code", "unknown")
        raise RuntimeError(f"Kakao API request failed for channel {masked} with status {status}.") from error

    try:
        payload = response.json()
    except ValueError as error:
        preview = response.text[:300].replace("\n", " ")
        raise RuntimeError(f"Kakao API did not return JSON for channel {masked}. Preview: {preview}") from error

    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected Kakao API response type for channel {masked}: {type(payload).__name__}")
    return payload


def content_parts_to_text(contents: Any) -> str:
    if not isinstance(contents, list):
        return ""
    parts: list[str] = []
    for part in contents:
        if not isinstance(part, dict):
            continue
        value = str(part.get("v", "") or "").strip()
        if value:
            parts.append(value)
    return clean_text("\n".join(parts), max_len=1800)


def best_image_url(media: Any) -> str:
    if not isinstance(media, list):
        return ""
    for item in media:
        if not isinstance(item, dict) or item.get("type") != "image":
            continue
        for key in ("xlarge_url", "large_url", "url", "medium_url", "small_url"):
            url = str(item.get(key, "") or "").strip()
            if url:
                return url.replace("http://", "https://", 1)
    return ""


def default_post_url(profile_id: str, post_id: str) -> str:
    return f"https://pf.kakao.com/{quote(profile_id, safe='')}/{quote(post_id, safe='')}"


def parse_post(raw: dict[str, Any], *, profile_id: str, tz_name: str) -> KakaoPost | None:
    post_id = str(raw.get("id", "") or "").strip()
    if not post_id:
        return None

    title = clean_text(str(raw.get("title", "") or ""), max_len=220)
    body = content_parts_to_text(raw.get("contents"))
    permalink = str(raw.get("permalink", "") or "").strip() or default_post_url(profile_id, post_id)
    permalink = permalink.replace("http://", "https://", 1)

    published_raw = raw.get("published_at")
    updated_raw = raw.get("updated_at")
    created_raw = raw.get("created_at")
    published_at = timestamp_ms_to_text(published_raw, tz_name)

    if not title:
        first_line = body.splitlines()[0].strip() if body else ""
        title = clean_text(first_line, max_len=120) or f"카카오 채널 새 소식 {post_id}"

    return KakaoPost(
        post_id=post_id,
        url=permalink,
        title=title,
        body=body,
        published_at=published_at,
        image_url=best_image_url(raw.get("media")),
        raw_published_at=int(published_raw) if isinstance(published_raw, int) else None,
        raw_updated_at=int(updated_raw) if isinstance(updated_raw, int) else None,
        raw_created_at=int(created_raw) if isinstance(created_raw, int) else None,
    )


def extract_api_posts(payload: dict[str, Any], *, profile_id: str, tz_name: str) -> list[KakaoPost]:
    """Support both /web/profiles/{id}/posts and /web/v2/profiles/{id} payloads."""
    raw_posts: list[Any] = []

    if isinstance(payload.get("items"), list):
        raw_posts = payload["items"]

    if not raw_posts and isinstance(payload.get("cards"), list):
        for card in payload["cards"]:
            if isinstance(card, dict) and card.get("type") == "post" and isinstance(card.get("posts"), list):
                raw_posts = card["posts"]
                break

    posts: list[KakaoPost] = []
    seen: set[str] = set()
    for raw in raw_posts:
        if not isinstance(raw, dict):
            continue
        post = parse_post(raw, profile_id=profile_id, tz_name=tz_name)
        if post is None or post.post_id in seen:
            continue
        seen.add(post.post_id)
        posts.append(post)
    return posts


def fetch_posts(target: ChannelTarget, *, tz_name: str) -> list[KakaoPost]:
    masked = target.target_key[:12]
    log(f"Fetching Kakao posts API for channel {masked}.")
    payload = fetch_json(target)
    posts = extract_api_posts(payload, profile_id=target.profile_id, tz_name=tz_name)
    if not posts:
        raise RuntimeError(f"No Kakao posts were extracted for channel {masked}.")
    return posts


def build_discord_payload(post: KakaoPost, *, channel_url: str, tz_name: str) -> dict[str, Any]:
    title = clean_text(post.title, max_len=250) or "카카오 채널 새 소식"
    body = clean_text(post.body, max_len=1500)
    published = post.published_at or "알 수 없음"

    content_lines = [
        f"{discord_mention()}{LEVEL_ICON['new']} **카카오 채널 새 소식 감지**",
        f"> {title}",
        post.url,
    ]

    embed: dict[str, Any] = {
        "title": title[:256],
        "url": post.url,
        "description": body or "내용 미리보기가 없습니다.",
        "fields": [
            {"name": "게시글 ID", "value": f"`{post.post_id}`", "inline": True},
            {"name": "게시 시각", "value": f"`{published}`", "inline": True},
            {"name": "확인 시각", "value": f"`{now_text(tz_name)}`", "inline": True},
            {"name": "채널", "value": channel_url, "inline": False},
        ],
    }
    if post.image_url:
        embed["image"] = {"url": post.image_url}

    return {
        "content": "\n".join(content_lines)[:1900],
        "embeds": [embed],
        "allowed_mentions": allowed_mentions(),
    }


def build_system_payload(*, title: str, body: str, level: str, tz_name: str) -> dict[str, Any]:
    icon = LEVEL_ICON.get(level, "ℹ️")
    return {
        "content": "\n".join(
            [
                f"{discord_mention()}{icon} **{title}**",
                f"> {body}",
                "",
                f"**Time:** `{now_text(tz_name)}`",
            ]
        ),
        "allowed_mentions": allowed_mentions(),
    }


def send_discord(payload: dict[str, Any]) -> None:
    webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook:
        raise RuntimeError("DISCORD_WEBHOOK_URL secret is empty.")
    response = requests.post(webhook, json=payload, timeout=20)
    response.raise_for_status()


def trim_seen_ids(seen_ids: set[str], current_posts: list[KakaoPost]) -> set[str]:
    """Prevent the in-memory set from growing without bound during a long run."""
    if len(seen_ids) <= MAX_SEEN_IDS_PER_CHANNEL:
        return seen_ids
    current_ids = [post.post_id for post in current_posts]
    kept = list(dict.fromkeys(current_ids + list(seen_ids)))[:MAX_SEEN_IDS_PER_CHANNEL]
    return set(kept)


def check_target_once(
    target: ChannelTarget,
    seen_by_channel: dict[str, set[str]],
    *,
    tz_name: str,
    notify_on_bootstrap: bool,
) -> tuple[int, bool]:
    masked = target.target_key[:12]
    current_posts = fetch_posts(target, tz_name=tz_name)
    current_ids = {post.post_id for post in current_posts}

    if target.target_key not in seen_by_channel:
        seen_by_channel[target.target_key] = set(current_ids)
        log(f"Baseline listed for channel {masked}. Existing posts: {len(current_ids)}. No old-news alerts sent.")
        if notify_on_bootstrap:
            send_discord(
                build_system_payload(
                    title="카카오 채널 감시 기준 목록 생성 완료",
                    body=(
                        f"채널 {masked}의 기존 소식 {len(current_ids)}개를 이번 실행의 기준 목록으로 메모리에 저장했습니다. "
                        "이번 실행 중 새로 올라오는 소식만 알림을 보냅니다."
                    ),
                    level="success",
                    tz_name=tz_name,
                )
            )
        return 0, True

    seen_ids = seen_by_channel[target.target_key]
    new_posts = [post for post in current_posts if post.post_id not in seen_ids]

    sent = 0
    if new_posts:
        for post in reversed(new_posts):
            send_discord(build_discord_payload(post, channel_url=target.channel_url, tz_name=tz_name))
            seen_ids.add(post.post_id)
            sent += 1
            log(f"Discord alert sent for channel {masked}, post {post.post_id}.")
    else:
        log(f"No new Kakao posts for channel {masked}.")

    # 현재 API에 보이는 모든 id도 seen에 합쳐서 같은 실행 안에서 중복 알림을 막습니다.
    seen_ids.update(current_ids)
    seen_by_channel[target.target_key] = trim_seen_ids(seen_ids, current_posts)
    log(f"Done for channel {masked}. Current posts: {len(current_posts)}, new alerts: {sent}.")
    return sent, True


def run_once(
    targets: list[ChannelTarget],
    seen_by_channel: dict[str, set[str]],
    *,
    tz_name: str,
    notify_on_bootstrap: bool,
) -> int:
    if not targets:
        raise RuntimeError("No Kakao profile ids configured. Set the KAKAO_PROFILE_IDS GitHub Secret.")

    total_sent = 0
    success_count = 0
    errors: list[str] = []

    for target in targets:
        try:
            sent, success = check_target_once(
                target,
                seen_by_channel,
                tz_name=tz_name,
                notify_on_bootstrap=notify_on_bootstrap,
            )
            total_sent += sent
            if success:
                success_count += 1
        except Exception as error:
            masked = target.target_key[:12]
            errors.append(f"{masked}: {error}")
            log(f"Channel {masked} failed: {error}")
            log(traceback.format_exc())

    if success_count == 0:
        raise RuntimeError("All configured Kakao channels failed. " + " | ".join(errors[:3]))

    if errors:
        log(f"Some channels failed, but {success_count}/{len(targets)} channel(s) succeeded.")

    log(f"All-channel check finished. channels={len(targets)}, successes={success_count}, alerts={total_sent}.")
    return total_sent


def run_loop(
    targets: list[ChannelTarget],
    *,
    tz_name: str,
    notify_on_bootstrap: bool,
    interval_seconds: int,
    duration_seconds: int,
    error_discord: bool,
    error_alert_cooldown_seconds: int,
) -> int:
    """Run checks repeatedly inside one GitHub Actions execution.

    No state file is read or committed. At the start of each execution, the first
    successful check lists current posts into memory. During that same execution,
    later checks compare against the in-memory baseline and alert only for new ids.
    """
    started = time.monotonic()
    deadline = started + duration_seconds
    iteration = 0
    success_count = 0
    error_count = 0
    last_error_alert_at = 0.0
    seen_by_channel: dict[str, set[str]] = {}

    log(
        "Loop mode enabled. "
        f"channels={len(targets)}, interval={interval_seconds}s, duration={duration_seconds}s, "
        "state=memory-only"
    )

    while True:
        if time.monotonic() >= deadline:
            break

        iteration += 1
        log(f"Loop check #{iteration} started.")
        try:
            run_once(
                targets,
                seen_by_channel,
                tz_name=tz_name,
                notify_on_bootstrap=notify_on_bootstrap,
            )
            success_count += 1
        except Exception as error:
            error_count += 1
            log(f"Loop check #{iteration} failed: {error}")
            log(traceback.format_exc())

            can_send_error = (
                error_discord
                and os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
                and time.monotonic() - last_error_alert_at >= error_alert_cooldown_seconds
            )
            if can_send_error:
                try:
                    send_discord(
                        build_system_payload(
                            title="카카오 채널 감시 오류",
                            body=f"반복 감시 중 오류가 발생했습니다. 다음 주기에서 다시 시도합니다.\n\n{error}",
                            level="error",
                            tz_name=tz_name,
                        )
                    )
                    last_error_alert_at = time.monotonic()
                except Exception as discord_error:
                    log(f"Failed to send error alert to Discord: {discord_error}")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sleep_seconds = min(interval_seconds, remaining)
        log(f"Sleeping {sleep_seconds:.0f}s before next check.")
        time.sleep(sleep_seconds)

    log(
        "Loop mode finished. "
        f"checks={iteration}, successes={success_count}, errors={error_count}."
    )
    return 0 if success_count > 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Kakao Channel JSON API new-post Discord notifier")
    parser.add_argument(
        "--profile-ids",
        default="",
        help="Comma, space, or newline separated Kakao profile ids. Prefer KAKAO_PROFILE_IDS secret in GitHub Actions.",
    )
    parser.add_argument("--timezone", default=os.environ.get("TIMEZONE", DEFAULT_TIMEZONE))
    parser.add_argument(
        "--notify-on-bootstrap",
        action="store_true",
        default=env_bool("KAKAO_NOTIFY_ON_BOOTSTRAP", False),
        help="Send a Discord message after this execution builds its in-memory baseline. Default: false.",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        default=env_bool("KAKAO_LOOP", False),
        help="Keep running and check repeatedly inside one workflow execution.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=env_int("CHECK_INTERVAL_SECONDS", DEFAULT_CHECK_INTERVAL_SECONDS, minimum=1),
        help="Seconds between checks in --loop mode. Default: 60.",
    )
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=env_int("RUN_DURATION_SECONDS", DEFAULT_RUN_DURATION_SECONDS, minimum=1),
        help="Maximum runtime in --loop mode. Default: 21480, 358 minutes.",
    )
    parser.add_argument(
        "--error-alert-cooldown-seconds",
        type=int,
        default=env_int("ERROR_ALERT_COOLDOWN_SECONDS", DEFAULT_ERROR_ALERT_COOLDOWN_SECONDS, minimum=1),
        help="Minimum seconds between Discord error alerts in --loop mode. Default: 1800.",
    )
    parser.add_argument(
        "--no-error-discord",
        action="store_true",
        help="Do not send Discord error alerts.",
    )
    args = parser.parse_args()

    profile_ids = split_profile_ids(args.profile_ids) if args.profile_ids.strip() else load_profile_ids_from_env()
    targets = build_targets(profile_ids)

    try:
        if args.loop:
            return run_loop(
                targets,
                tz_name=args.timezone,
                notify_on_bootstrap=args.notify_on_bootstrap,
                interval_seconds=args.interval_seconds,
                duration_seconds=args.duration_seconds,
                error_discord=not args.no_error_discord,
                error_alert_cooldown_seconds=args.error_alert_cooldown_seconds,
            )

        # One-shot mode has no previous state to compare against, so it only builds the baseline in memory.
        run_once(
            targets,
            {},
            tz_name=args.timezone,
            notify_on_bootstrap=args.notify_on_bootstrap,
        )
        return 0
    except Exception as error:
        log(f"Fatal: {error}")
        log(traceback.format_exc())
        if not args.no_error_discord and os.environ.get("DISCORD_WEBHOOK_URL", "").strip():
            try:
                send_discord(
                    build_system_payload(
                        title="카카오 채널 감시 오류",
                        body=str(error),
                        level="error",
                        tz_name=args.timezone,
                    )
                )
            except Exception as discord_error:
                log(f"Failed to send error alert to Discord: {discord_error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
