import time
from pathlib import Path

import click

from esim.analysis import Session
from esim.capture import Capture
from esim.device import ADBError, Device


@click.group()
@click.option("--serial", "-s", default=None, help="ADB device serial")
@click.pass_context
def main(ctx, serial: str | None) -> None:
    ctx.ensure_object(dict)
    ctx.obj["serial"] = serial


def _device(ctx: click.Context) -> Device:
    return Device(serial=ctx.obj.get("serial"))


@main.command()
@click.pass_context
def eid(ctx) -> None:
    """Print the eUICC identifier."""
    try:
        click.echo(_device(ctx).get_eid())
    except ADBError as e:
        raise click.ClickException(str(e))


@main.group()
def profiles() -> None:
    """Manage eSIM profiles."""


@profiles.command("list")
@click.pass_context
def profiles_list(ctx) -> None:
    """List all subscriptions."""
    try:
        subs = _device(ctx).list_subscriptions()
        click.echo(f"{'NAME':<20} {'ICCID':<22} {'SLOT':>5} {'ESIM':>6}")
        for s in subs:
            click.echo(
                f"{s.display_name:<20} {s.iccid:<22} {s.slot:>5} "
                f"{'yes' if s.is_esim else 'no':>6}"
            )
    except ADBError as e:
        raise click.ClickException(str(e))


@profiles.command("enable")
@click.argument("sub_id", type=int)
@click.pass_context
def profiles_enable(ctx, sub_id: int) -> None:
    """Enable an eSIM profile."""
    try:
        _device(ctx).enable_profile(sub_id)
        click.echo(f"Profile {sub_id} enabled.")
    except ADBError as e:
        raise click.ClickException(str(e))


@profiles.command("disable")
@click.argument("sub_id", type=int)
@click.pass_context
def profiles_disable(ctx, sub_id: int) -> None:
    """Disable an eSIM profile."""
    try:
        _device(ctx).disable_profile(sub_id)
        click.echo(f"Profile {sub_id} disabled.")
    except ADBError as e:
        raise click.ClickException(str(e))


@main.command("data-sim")
@click.argument("sub_id", type=int)
@click.pass_context
def data_sim(ctx, sub_id: int) -> None:
    """Set the default data SIM."""
    try:
        _device(ctx).set_data_sim(sub_id)
        click.echo(f"Data SIM set to subscription {sub_id}.")
    except ADBError as e:
        raise click.ClickException(str(e))


@main.command()
@click.option("--port", default=8080, show_default=True)
@click.option("--filter", "filters", multiple=True, default=["ES9+", "ES11"])
@click.option("--out", "out_dir", default=None, type=click.Path())
@click.pass_context
def capture(ctx, port: int, filters: tuple, out_dir: str | None) -> None:
    """Start a capture session. Ctrl-C to stop."""
    d = _device(ctx)
    try:
        with Capture(device=d, port=port, filters=list(filters)) as cap:
            click.echo(f"Capturing on :{port} — Ctrl-C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        session = cap.save(Path(out_dir) if out_dir else None)
        click.echo(f"Session saved: {session.session_dir}")
    except ADBError as e:
        raise click.ClickException(str(e))


@main.command()
@click.argument("session_path", type=click.Path(exists=True))
def analyze(session_path: str) -> None:
    """Analyze a saved capture session."""
    s = Session.load(session_path)
    click.echo(f"ES11 calls:    {len(s.es11_calls())}")
    click.echo(f"ES9+ calls:    {len(s.es9_calls())}")
    click.echo(f"BPP blobs:     {len(s.bpp_blobs())}")
    click.echo(f"Logcat events: {len(s.logcat_events())}")
    for c in s.es11_calls():
        click.echo(f"  ES11  {c.method}")
    for c in s.es9_calls():
        click.echo(f"  ES9+  {c.method}")


@main.command()
@click.option("--out", "out_dir", default="sessions", show_default=True, type=click.Path())
@click.pass_context
def bugreport(ctx, out_dir: str) -> None:
    """Capture a telephony bugreport."""
    try:
        path = _device(ctx).bugreport(Path(out_dir))
        click.echo(f"Saved: {path}")
    except ADBError as e:
        raise click.ClickException(str(e))


if __name__ == "__main__":
    main()
