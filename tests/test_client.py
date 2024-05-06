import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pprint import pprint
from time import sleep

import pytest
from sd_core.models import Event

logging.basicConfig(level=logging.WARN)

# TODO: Could it be possible to write a sisterclass of ActivityWatchClient
# which calls sd_server.api directly? Would it be of use? Would add another
# layer of integration tests that are actually more like unit tests.


@pytest.fixture(scope="function")
def bucket(sd_client):
    bucket_id = "test-" + str(random.randint(0, 10**5))
    event_type = "testevents"
    sd_client.create_bucket(bucket_id, event_type, queued=False)
    print(f"Created bucket {bucket_id}")
    sleep(1)
    yield bucket_id
    sd_client.delete_bucket(bucket_id)


@pytest.fixture
def queued_bucket(sd_client, bucket):
    # FIXME: We need a way to clear the failed_requests file in order
    # to have tests behave reasonably between runs.
    sd_client.connect()
    yield bucket
    sd_client.disconnect()


def test_get_info(sd_client):
    info = sd_client.get_info()
    assert info["testing"]


def test_export(sd_client):
    export = sd_client._get("export").json()
    for bucket_id, bucket in export["buckets"].items():
        assert bucket["id"]
        assert "events" in bucket
    # print(export)


def _create_heartbeat_events(
    start=datetime.now(tz=timezone.utc), delta=timedelta(seconds=1)
):
    e1_ts = start
    e2_ts = e1_ts + delta

    # Needed since server (or underlying datastore) drops precision up to milliseconds.
    # Update: Even with millisecond precision it sometimes fails. (tried using `round` and `int`)
    #         Now rounding down to 10ms precision to prevent random failure.
    #         10ms precision at least seems to work well.
    # TODO: Figure out why it sometimes fails with millisecond precision. Would probably
    #       be useful to find the microsecond values where it consistently always fails.
    e1_ts = e1_ts.replace(microsecond=int(e1_ts.microsecond / 10000) * 100)
    e2_ts = e2_ts.replace(microsecond=int(e2_ts.microsecond / 10000) * 100)

    e1 = Event(timestamp=e1_ts, data={"label": "test"})
    e2 = Event(timestamp=e2_ts, data={"label": "test"})

    return e1, e2


def _create_periodic_events(
    num_events, start=datetime.now(tz=timezone.utc), delta=timedelta(hours=1)
):
    events = num_events * [None]

    for i, dt in ((i, start + i * delta) for i in range(len(events))):
        events[i] = Event(timestamp=dt, duration=delta, data={"label": "test"})

    return events


def test_heartbeat(sd_client, bucket):
    bucket_id = bucket

    e1, e2 = _create_heartbeat_events()

    sd_client.heartbeat(bucket_id, e1, pulsetime=0)
    sd_client.heartbeat(bucket_id, e2, pulsetime=10)

    event = sd_client.get_events(bucket_id, limit=1)[0]

    assert event.timestamp == e1.timestamp
    assert event.duration == e2.timestamp - e1.timestamp


def test_heartbeat_random_order(sd_client, bucket):
    bucket_id = bucket

    # All the events will have the same data
    events = _create_periodic_events(100, delta=timedelta(seconds=1))
    random.shuffle(events)

    for e in events:
        sd_client.heartbeat(bucket_id, e, pulsetime=2)

    events = sd_client.get_events(bucket_id, limit=-1)

    # FIXME: This should pass
    # assert len(events) == 1


def test_queued_heartbeat(sd_client, queued_bucket):
    bucket_id = queued_bucket

    e1, e2 = _create_heartbeat_events()

    sd_client.heartbeat(bucket_id, e1, pulsetime=0, queued=True)
    sd_client.heartbeat(bucket_id, e2, pulsetime=10, queued=True)

    # Needed because of sd_client-side heartbeat merging and delayed dispatch
    sd_client.heartbeat(
        bucket_id,
        Event(timestamp=e2.timestamp, data={"label": "something different"}),
        pulsetime=0,
        queued=True,
    )

    # Needed since the dispatcher thread might introduce some delay
    max_tries = 20
    for i in range(max_tries):
        events = sd_client.get_events(bucket_id, limit=1)
        if len(events) > 0 and events[0].duration > timedelta(seconds=0):
            break
        sleep(0.5)

    assert i != max_tries - 1
    print(f"Done on the {i + 1}th try")

    assert len(events) == 1
    event = events[0]

    assert event.timestamp == e1.timestamp
    assert event.duration == e2.timestamp - e1.timestamp


def test_list_buckets(sd_client, bucket):
    buckets = sd_client.get_buckets()
    assert bucket in buckets.keys()


def test_insert_event(sd_client, bucket):
    event = Event(timestamp=datetime.now(tz=timezone.utc), data={"label": "test"})
    sd_client.insert_event(bucket, event)
    recv_events = sd_client.get_events(bucket, limit=1)
    assert recv_events == [event]


def test_insert_events(sd_client, bucket):
    events = _create_periodic_events(
        2, start=datetime.now(tz=timezone.utc) - timedelta(days=1)
    )

    sd_client.insert_events(bucket, events)
    recv_events = sd_client.get_events(bucket)

    # Why isn't reverse=True needed here?
    assert events == sorted(recv_events, key=lambda e: e.timestamp)


def test_get_event_single(sd_client, bucket):
    start_dt = datetime.now(tz=timezone.utc) - timedelta(days=50)
    delta = timedelta(hours=1)
    events = _create_periodic_events(10, delta=delta, start=start_dt)

    sd_client.insert_events(bucket, events)

    events = sd_client.get_events(bucket)

    for e in events:
        e2 = sd_client.get_event(bucket, e.id)
        assert e.id == e2.id
        assert e.timestamp == e2.timestamp
        assert e.duration == e2.duration
        assert e.data == e2.data


def test_get_events_interval(sd_client, bucket):
    start_dt = datetime.now(tz=timezone.utc) - timedelta(days=50)
    end_dt = start_dt + timedelta(days=1)
    delta = timedelta(hours=1)
    events = _create_periodic_events(1000, delta=delta, start=start_dt)

    sd_client.insert_events(bucket, events)

    # start kwarg isn't currently range-inclusive
    recv_events = sd_client.get_events(bucket, limit=50, start=start_dt, end=end_dt)

    assert len(recv_events) == 25

    # drop IDs
    for e in recv_events:
        e.id = None
    print(recv_events)
    src_events = sorted(events[:25], reverse=True, key=lambda e: e.timestamp)

    # The first event gets cut off
    assert recv_events[0].timestamp == src_events[0].timestamp
    assert recv_events[0].data == src_events[0].data

    # This fails due to microsecond precision issues
    assert _round_td(recv_events[0].duration) == _round_td(
        end_dt - recv_events[0].timestamp
    )

    # NOTE: Duration can differ by a few microseconds, so we round durations off to 10ms
    recv_events = [_round_durations(e) for e in recv_events]
    src_events = [_round_durations(e) for e in src_events]

    assert recv_events[1:25] == src_events[1:25]


def _round_td(td: timedelta) -> timedelta:
    return timedelta(seconds=round(td.total_seconds(), 2))


def _round_durations(e: Event):
    e.duration = _round_td(e.duration)
    return e


def test_store_many_events(sd_client, bucket):
    events = _create_periodic_events(
        1000, start=datetime.now(tz=timezone.utc) - timedelta(days=50)
    )

    sd_client.insert_events(bucket, events)
    recv_events = sd_client.get_events(bucket, limit=-1)

    assert len(events) == len(recv_events)
    assert recv_events == sorted(events, reverse=True, key=lambda e: e.timestamp)


def test_midnight(sd_client, bucket):
    start_dt = datetime.now() - timedelta(days=1)
    midnight = start_dt.replace(hour=23, minute=50)
    events = _create_periodic_events(100, start=midnight, delta=timedelta(minutes=1))

    sd_client.insert_events(bucket, events)
    recv_events = sd_client.get_events(bucket, limit=-1)
    assert len(recv_events) == len(events)


def test_midnight_heartbeats(sd_client, bucket):
    now = datetime.now(tz=timezone.utc) - timedelta(days=1)
    midnight = now.replace(hour=23, minute=50)
    events = _create_periodic_events(20, start=midnight, delta=timedelta(minutes=1))

    label_ring = ["1", "1", "2", "3", "4"]
    for i, e in enumerate(events):
        e.data["label"] = label_ring[i % len(label_ring)]
        sd_client.heartbeat(bucket, e, pulsetime=90)

    recv_events_merged = sd_client.get_events(bucket, limit=-1)
    assert len(recv_events_merged) == 4 / 5 * len(events)

    recv_events_after_midnight = sd_client.get_events(
        bucket, start=midnight + timedelta(minutes=10)
    )
    pprint(recv_events_after_midnight)
    assert len(recv_events_after_midnight) == int(len(recv_events_merged) / 2)


def test_settings(sd_client):
    sd_client.set_setting("test", "test")
    sd_client.set_setting("list", json.dumps([1, 2, 3]))
    sd_client.set_setting("dict", json.dumps({"a": 1, "b": 2}))

    # check set
    assert sd_client.get_setting("test") == "test"
    assert json.loads(sd_client.get_setting("list")) == [1, 2, 3]
    assert json.loads(sd_client.get_setting("dict")) == {"a": 1, "b": 2}

    # check unset
    assert sd_client.get_setting("test2") is None

    # check get all
    settings = sd_client.get_setting()
    assert settings["test"] == "test"
    assert json.loads(settings["list"]) == [1, 2, 3]
    assert json.loads(settings["dict"]) == {"a": 1, "b": 2}
