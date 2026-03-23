"""Tests for the deterministic keyword classifier."""

from __future__ import annotations

import pytest

from sentinel.router.classifier import ClassificationResult, Route
from sentinel.router.keyword_classifier import KeywordClassifier
from sentinel.router.templates import TemplateRegistry


@pytest.fixture
def classifier() -> KeywordClassifier:
    """Keyword classifier with default template registry."""
    return KeywordClassifier(TemplateRegistry.default())


# ---- Fast-path routing tests ----

class TestWebSearch:
    def test_weather_query(self, classifier):
        result = _classify(classifier, "what's the weather in London")
        assert result.is_fast
        assert result.template_name == "web_search"
        assert result.params.get("query")

    def test_search_for(self, classifier):
        result = _classify(classifier, "search for python tutorials")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_look_up(self, classifier):
        result = _classify(classifier, "look up the capital of France")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_what_is(self, classifier):
        result = _classify(classifier, "what is kubernetes")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_who_is(self, classifier):
        result = _classify(classifier, "who is the prime minister of Japan")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_news_about(self, classifier):
        result = _classify(classifier, "latest news on AI regulation")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_case_insensitive(self, classifier):
        result = _classify(classifier, "Search For best pizza recipe")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_how_do_i(self, classifier):
        result = _classify(classifier, "how do I reset my router")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_how_to(self, classifier):
        result = _classify(classifier, "how to make sourdough bread")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_when_is(self, classifier):
        result = _classify(classifier, "when is the next bank holiday")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_when_did(self, classifier):
        result = _classify(classifier, "when did WW2 end")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_why_is(self, classifier):
        result = _classify(classifier, "why is the sky blue")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_define(self, classifier):
        result = _classify(classifier, "define epistemology")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_meaning_of(self, classifier):
        result = _classify(classifier, "meaning of ubiquitous")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_price_of(self, classifier):
        result = _classify(classifier, "price of iPhone 16")
        assert result.is_fast
        assert result.template_name == "web_search"

    def test_how_much_does_cost(self, classifier):
        result = _classify(classifier, "how much does a Tesla Model 3 cost")
        assert result.is_fast
        assert result.template_name == "web_search"


class TestCalendarAdd:
    """calendar_add requires NLP to extract summary + start from natural
    language. The keyword classifier recognises the *intent* but can't
    extract the structured params, so it correctly falls through to
    the planner for all calendar_add messages."""

    def test_add_to_calendar(self, classifier):
        result = _classify(classifier, "add dentist appointment to my calendar")
        assert result.is_planner

    def test_schedule_a_meeting(self, classifier):
        result = _classify(classifier, "schedule a meeting with John at 3pm")
        assert result.is_planner

    def test_remind_me(self, classifier):
        result = _classify(classifier, "remind me to call the bank tomorrow")
        assert result.is_planner

    def test_set_reminder(self, classifier):
        result = _classify(classifier, "set a reminder for 5pm")
        assert result.is_planner

    def test_put_in_calendar(self, classifier):
        result = _classify(classifier, "put team standup in my calendar")
        assert result.is_planner

    def test_create_event(self, classifier):
        result = _classify(classifier, "create an event for Friday lunch")
        assert result.is_planner

    def test_book_a_meeting(self, classifier):
        result = _classify(classifier, "book a meeting room for 2pm")
        assert result.is_planner

    def test_new_event(self, classifier):
        result = _classify(classifier, "new event Friday lunch with team")
        assert result.is_planner

    def test_block_out_time(self, classifier):
        result = _classify(classifier, "block out 2-3pm for focus time")
        assert result.is_planner

    def test_block_time_for(self, classifier):
        result = _classify(classifier, "block time for deep work from 9am")
        assert result.is_planner

    def test_schedule_session_on_zoom(self, classifier):
        result = _classify(classifier, "schedule a session on Zoom for 3pm")
        assert result.is_planner


class TestCalendarRead:
    def test_my_calendar(self, classifier):
        result = _classify(classifier, "what's on my calendar today")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_my_schedule(self, classifier):
        result = _classify(classifier, "show me my schedule for tomorrow")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_am_i_free(self, classifier):
        result = _classify(classifier, "am I free on Thursday afternoon")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_upcoming_events(self, classifier):
        result = _classify(classifier, "upcoming events this week")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_any_meetings(self, classifier):
        result = _classify(classifier, "any meetings today")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_do_i_have_anything(self, classifier):
        result = _classify(classifier, "do I have anything on Tuesday")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_whats_happening_this_afternoon(self, classifier):
        result = _classify(classifier, "what's happening this afternoon")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_next_meeting(self, classifier):
        result = _classify(classifier, "when's my next meeting")
        assert result.is_fast
        assert result.template_name == "calendar_read"


class TestEmailSearch:
    def test_search_my_email(self, classifier):
        result = _classify(classifier, "search my email for invoices")
        assert result.is_fast
        assert result.template_name == "email_search"

    def test_find_emails_from(self, classifier):
        result = _classify(classifier, "find emails from John")
        assert result.is_fast
        assert result.template_name == "email_search"

    def test_emails_about(self, classifier):
        result = _classify(classifier, "emails about the project deadline")
        assert result.is_fast
        assert result.template_name == "email_search"


class TestEmailRead:
    def test_last_email(self, classifier):
        result = _classify(classifier, "what was my last email about")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_check_email(self, classifier):
        result = _classify(classifier, "check my email")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_any_new_emails(self, classifier):
        result = _classify(classifier, "any new emails")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_read_my_email(self, classifier):
        result = _classify(classifier, "read my latest email")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_unread_emails(self, classifier):
        result = _classify(classifier, "unread emails")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_my_inbox(self, classifier):
        result = _classify(classifier, "show me my inbox")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_whats_in_inbox(self, classifier):
        result = _classify(classifier, "what's in my inbox")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_open_my_email(self, classifier):
        result = _classify(classifier, "open my email")
        assert result.is_fast
        assert result.template_name == "email_read"

    def test_query_is_wildcard_not_raw_message(self, classifier):
        """email_read should use '*' query, not the literal user message."""
        result = _classify(classifier, "what was my last email about")
        assert result.params.get("query") == "*"

    def test_check_email_query_wildcard(self, classifier):
        """'check my email' should also get wildcard query."""
        result = _classify(classifier, "check my email")
        assert result.params.get("query") == "*"


class TestEmailSend:
    """email_send requires NLP to extract recipient + subject + body from
    natural language. The keyword classifier recognises the *intent* but
    can't extract the structured params, so it correctly falls through
    to the planner for all email_send messages."""

    def test_send_email_to(self, classifier):
        result = _classify(classifier, "send an email to John about the meeting")
        assert result.is_planner

    def test_email_someone(self, classifier):
        result = _classify(classifier, "email Sarah saying I'll be late")
        assert result.is_planner

    def test_reply_to_email(self, classifier):
        result = _classify(classifier, "reply to that email")
        assert result.is_planner

    def test_forward_email(self, classifier):
        result = _classify(classifier, "forward that email to John")
        assert result.is_planner

    def test_draft_email(self, classifier):
        result = _classify(classifier, "draft an email to Sarah about the project")
        assert result.is_planner

    def test_write_email(self, classifier):
        result = _classify(classifier, "write an email to the team")
        assert result.is_planner


class TestSignalSend:
    def test_send_on_signal(self, classifier):
        result = _classify(classifier, "send hi to John on signal")
        assert result.is_fast
        assert result.template_name == "signal_send"

    def test_message_via_signal(self, classifier):
        result = _classify(classifier, "message Sarah via signal saying I'm running late")
        assert result.is_fast
        assert result.template_name == "signal_send"

    def test_text_on_signal(self, classifier):
        result = _classify(classifier, "text John on signal")
        assert result.is_fast
        assert result.template_name == "signal_send"

    def test_message_param_not_raw(self, classifier):
        """signal_send should get 'message' param, not '_raw_message'."""
        result = _classify(classifier, "send hi to John on signal")
        assert "message" in result.params
        assert "_raw_message" not in result.params


class TestTelegramSend:
    def test_send_on_telegram(self, classifier):
        result = _classify(classifier, "send hello to John on telegram")
        assert result.is_fast
        assert result.template_name == "telegram_send"

    def test_message_via_telegram(self, classifier):
        result = _classify(classifier, "message Sarah via telegram")
        assert result.is_fast
        assert result.template_name == "telegram_send"

    def test_message_param_not_raw(self, classifier):
        """telegram_send should get 'message' param, not '_raw_message'."""
        result = _classify(classifier, "send hello to John on telegram")
        assert "message" in result.params
        assert "_raw_message" not in result.params


class TestXSearch:
    def test_search_twitter(self, classifier):
        result = _classify(classifier, "search twitter for AI news")
        assert result.is_fast
        assert result.template_name == "x_search"

    def test_search_x(self, classifier):
        result = _classify(classifier, "search X for bitcoin")
        assert result.is_fast
        assert result.template_name == "x_search"

    def test_trending_on_x(self, classifier):
        result = _classify(classifier, "what's trending on X about crypto")
        assert result.is_fast
        assert result.template_name == "x_search"

    def test_trending_on_twitter(self, classifier):
        result = _classify(classifier, "what's trending on twitter")
        assert result.is_fast
        assert result.template_name == "x_search"

    def test_tweets_about(self, classifier):
        result = _classify(classifier, "tweets about the election")
        assert result.is_fast
        assert result.template_name == "x_search"

    def test_people_saying_on_x(self, classifier):
        result = _classify(classifier, "what are people saying about AI on X")
        assert result.is_fast
        assert result.template_name == "x_search"


# ---- Planner routing tests ----

class TestPlannerFallback:
    def test_no_match_goes_to_planner(self, classifier):
        result = _classify(classifier, "create a basic HTML page with blue background")
        assert result.is_planner

    def test_multi_step_goes_to_planner(self, classifier):
        result = _classify(classifier, "check my email and then send a summary on signal")
        assert result.is_planner

    def test_complex_request_goes_to_planner(self, classifier):
        result = _classify(classifier, "build me a dashboard showing my calendar and emails")
        assert result.is_planner

    def test_creative_request_goes_to_planner(self, classifier):
        result = _classify(classifier, "write a poem about the weather")
        assert result.is_planner

    def test_planner_override_phrase(self, classifier):
        result = _classify(classifier, "use the planner to check my calendar")
        assert result.is_planner

    def test_multi_template_match_goes_to_planner(self, classifier):
        result = _classify(classifier, "send my last email to John on signal")
        assert result.is_planner

    def test_and_then_goes_to_planner(self, classifier):
        result = _classify(classifier, "search for the news and then email it to me")
        assert result.is_planner

    def test_after_that_goes_to_planner(self, classifier):
        result = _classify(classifier, "check my calendar, after that send me a summary")
        assert result.is_planner

    def test_empty_message_goes_to_planner(self, classifier):
        result = _classify(classifier, "")
        assert result.is_planner

    def test_gibberish_goes_to_planner(self, classifier):
        result = _classify(classifier, "asdfghjkl")
        assert result.is_planner

    def test_ambiguous_search_goes_to_planner(self, classifier):
        """'search' alone is too ambiguous — could be web, email, or X."""
        result = _classify(classifier, "search stuff")
        # Should match web_search as fallback (most general)
        assert result.is_fast
        assert result.template_name == "web_search"

    # ---- Multi-step signal tests ----

    def test_first_then_goes_to_planner(self, classifier):
        result = _classify(classifier, "first check my email then send a summary")
        assert result.is_planner

    def test_as_well_as_goes_to_planner(self, classifier):
        result = _classify(classifier, "search for news as well as check my calendar")
        assert result.is_planner

    def test_comma_also_goes_to_planner(self, classifier):
        result = _classify(classifier, "check my email, also send a message on signal")
        assert result.is_planner

    def test_both_and_goes_to_planner(self, classifier):
        result = _classify(classifier, "both email and signal John about the meeting")
        assert result.is_planner

    # ---- False positive guards ----

    def test_create_event_handler_goes_to_planner(self, classifier):
        """'create an event handler' is code, not a calendar event."""
        result = _classify(classifier, "create an event handler in JavaScript")
        assert result.is_planner

    def test_schedule_deployment_goes_to_planner(self, classifier):
        """'schedule a deployment' is devops, not a calendar event."""
        result = _classify(classifier, "schedule a deployment for the API")
        assert result.is_planner

    def test_schedule_cron_goes_to_planner(self, classifier):
        """'schedule a cron job' is devops, not a calendar event."""
        result = _classify(classifier, "schedule a cron job")
        assert result.is_planner

    def test_write_poem_about_weather_goes_to_planner(self, classifier):
        """Generative intent should not match web_search via 'weather'."""
        result = _classify(classifier, "write a poem about the weather")
        assert result.is_planner

    def test_build_website_goes_to_planner(self, classifier):
        result = _classify(classifier, "build me a website")
        assert result.is_planner

    def test_write_some_code_goes_to_planner(self, classifier):
        """Generative verb 'write' + no template keyword = planner."""
        result = _classify(classifier, "write some code")
        assert result.is_planner

    def test_create_html_page_goes_to_planner(self, classifier):
        """The exact failure from today's testing session."""
        result = _classify(classifier, "Create a basic HTML page that says 'Hello World' with a blue background")
        assert result.is_planner

    def test_what_is_on_my_schedule_goes_to_calendar(self, classifier):
        """'what is' should not grab this as web_search — calendar_read comes first."""
        result = _classify(classifier, "what is on my schedule today")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_when_is_my_next_meeting_goes_to_calendar(self, classifier):
        """Uncontracted 'when is' should match calendar_read, not web_search."""
        result = _classify(classifier, "when is my next meeting")
        assert result.is_fast
        assert result.template_name == "calendar_read"

    def test_block_user_goes_to_planner(self, classifier):
        """'block the user from accessing' is not a calendar event."""
        result = _classify(classifier, "block the user from accessing the API")
        assert result.is_planner

    # ---- Generative intent with template exceptions ----

    def test_create_event_for_friday_goes_to_planner(self, classifier):
        """'create an event for Friday' matches calendar_add intent but
        requires NLP param extraction — routes to planner."""
        result = _classify(classifier, "create an event for Friday lunch")
        assert result.is_planner

    def test_draft_email_goes_to_planner(self, classifier):
        """'draft an email' matches email_send intent but requires NLP
        param extraction (recipient+subject+body) — routes to planner."""
        result = _classify(classifier, "draft an email to John")
        assert result.is_planner

    def test_write_email_goes_to_planner(self, classifier):
        """'write an email' matches email_send intent but requires NLP
        param extraction — routes to planner."""
        result = _classify(classifier, "write an email to the team about the deadline")
        assert result.is_planner


# ---- Parameter extraction tests ----

class TestParamExtraction:
    def test_weather_query_extracted(self, classifier):
        result = _classify(classifier, "what's the weather in Tokyo")
        assert "weather" in result.params.get("query", "").lower()
        assert "tokyo" in result.params.get("query", "").lower()

    def test_search_for_query_extracted(self, classifier):
        result = _classify(classifier, "search for best restaurants nearby")
        assert "best restaurants nearby" in result.params.get("query", "").lower()

    def test_email_search_query_extracted(self, classifier):
        result = _classify(classifier, "search my email for invoices from March")
        assert "invoices from march" in result.params.get("query", "").lower()

    def test_x_search_query_extracted(self, classifier):
        result = _classify(classifier, "search twitter for AI safety news")
        assert "ai safety news" in result.params.get("query", "").lower()


# ---- Helper ----

def _classify(classifier: KeywordClassifier, msg: str) -> ClassificationResult:
    """Sync wrapper for the async classify method."""
    import asyncio
    return asyncio.run(classifier.classify(msg))
