"""Loot screen: users, credentials, hashes; add, edit and delete your own, copy, mark
verified / cracked (docs/UI.md screen 4).

Secrets are masked until you press v; they never leave the box folder except to your clipboard.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static

from cyberdeck.core import services
from cyberdeck.core.models import Finding, FindingType
from cyberdeck.core.options import OptionError
from cyberdeck.core.workspace import Workspace
from cyberdeck.ui.tui.modals import ConfirmModal, InputModal

LOOT_TYPES = (FindingType.USER, FindingType.CREDENTIAL, FindingType.HASH)

# field id -> (label, which loot types show it, placeholder)
_FIELDS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "user": ("Username", ("credential", "user", "hash"), "e.g. svc_backup (optional for a hash)"),
    "secret": ("Password / secret", ("credential",), "the password, key or token"),
    "realm": ("Domain / realm", ("credential", "user"), "optional, e.g. box.htb"),
    "where": ("Works on", ("credential",), "optional, e.g. ssh or smb (marks it verified)"),
    "value": ("Hash", ("hash",), "the hash as found, e.g. $2y$10$... or an NT hash"),
    "mode": ("Hashcat mode", ("hash",), "optional number, e.g. 1000 (NTLM), 3200 (bcrypt)"),
    "cracked": ("Cracked value", ("hash",), "optional, if you already have it"),
}

_REQUIRED = {"credential": ("user", "secret"), "user": ("user",), "hash": ("value",)}


def loot_payload(kind: str, fields: dict[str, str]) -> tuple[FindingType, dict[str, Any]]:
    """Form fields -> (finding type, payload data). Empty fields are left out, so the model's
    own validation reports what is missing."""
    f = {k: v.strip() for k, v in fields.items() if v and v.strip()}
    if kind == "user":
        return FindingType.USER, {"name": f.get("user"), "realm": f.get("realm")}
    if kind == "hash":
        return FindingType.HASH, {
            "value": f.get("value"),
            "user": f.get("user"),
            "hashcat_mode": f.get("mode"),
            "cracked": f.get("cracked"),
        }
    where = [w.strip() for w in f.get("where", "").split(",") if w.strip()]
    return FindingType.CREDENTIAL, {
        "user": f.get("user"),
        "secret": f.get("secret"),
        "kind": f.get("kind") or "password",
        "realm": f.get("realm"),
        "verified_on": where,
    }


def loot_fields(finding: Finding) -> tuple[str, dict[str, str]]:
    """A stored finding -> (form type, form field values), for editing."""
    d = finding.data

    def text(value: Any) -> str:
        return "" if value is None else str(value)

    if finding.type is FindingType.USER:
        return "user", {"user": text(d.get("name")), "realm": text(d.get("realm"))}
    if finding.type is FindingType.HASH:
        return "hash", {
            "value": text(d.get("value")),
            "user": text(d.get("user")),
            "mode": text(d.get("hashcat_mode")),
            "cracked": text(d.get("cracked")),
        }
    return "credential", {
        "user": text(d.get("user")),
        "secret": text(d.get("secret")),
        "kind": text(d.get("kind") or "password"),
        "realm": text(d.get("realm")),
        "where": ", ".join(d.get("verified_on") or []),
    }


class AddLootModal(ModalScreen[bool]):
    """Record a user, credential or hash you found yourself. ``save`` stores it and returns an
    error message (the form stays open) or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel"), Binding("ctrl+s", "save", "Save")]

    def __init__(
        self,
        save: Callable[[FindingType, dict[str, Any]], str | None],
        *,
        editing: Finding | None = None,
    ) -> None:
        super().__init__()
        self.save = save
        self.editing = editing

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog", id="add-loot"):
            yield Label("Edit loot" if self.editing else "Add loot", classes="dialog-title")
            with Horizontal(classes="row"):
                yield Label("Type", classes="opt-label")
                yield Select(
                    [("Credential", "credential"), ("User", "user"), ("Hash", "hash")],
                    value="credential",
                    allow_blank=False,
                    id="kind",
                    compact=True,
                )
            for fid, (label, _, placeholder) in _FIELDS.items():
                with Horizontal(classes="row", id=f"row-{fid}"):
                    yield Label(label, classes="opt-label")
                    yield Input(
                        placeholder=placeholder,
                        password=fid == "secret",
                        id=f"f-{fid}",
                        compact=True,
                    )
                if fid == "secret":
                    with Horizontal(classes="row", id="row-secret-kind"):
                        yield Label("Kind", classes="opt-label")
                        yield Select(
                            [(k, k) for k in ("password", "key", "token", "other")],
                            value="password",
                            allow_blank=False,
                            id="f-kind",
                            compact=True,
                        )
            yield Static(id="add-error")
            with Horizontal(classes="buttons"):
                yield Button("Save  ctrl+s", variant="primary", id="save", compact=True)
                yield Button("Cancel  esc", id="cancel", compact=True)

    def on_mount(self) -> None:
        kind = "credential"
        if self.editing is not None:
            kind, values = loot_fields(self.editing)
            kind_select = self.query_one("#kind", Select)
            kind_select.value = kind
            kind_select.disabled = True  # changing type = delete it and add a new one
            for fid, value in values.items():
                if fid == "kind":
                    self.query_one("#f-kind", Select).value = value or "password"
                else:
                    self.query_one(f"#f-{fid}", Input).value = value
        self._show(kind)
        first = "value" if kind == "hash" else "user"
        self.query_one(f"#f-{first}", Input).focus()

    def _kind(self) -> str:
        return str(self.query_one("#kind", Select).value)

    def _show(self, kind: str) -> None:
        for fid, (_, kinds, _) in _FIELDS.items():
            self.query_one(f"#row-{fid}").display = kind in kinds
        self.query_one("#row-secret-kind").display = kind == "credential"

    @on(Select.Changed, "#kind")
    def _kind_changed(self, event: Select.Changed) -> None:
        self._show(str(event.value))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_save()

    def action_save(self) -> None:
        kind = self._kind()
        fields = {
            fid: self.query_one(f"#f-{fid}", Input).value
            for fid, (_, kinds, _) in _FIELDS.items()
            if kind in kinds
        }
        missing = [_FIELDS[f][0] for f in _REQUIRED[kind] if not fields.get(f, "").strip()]
        if missing:
            self.query_one("#add-error", Static).update(
                Text("Needed: " + ", ".join(missing), style="red")
            )
            return
        fields["kind"] = str(self.query_one("#f-kind", Select).value)
        ftype, data = loot_payload(kind, fields)
        error = self.save(ftype, data)
        if error:
            self.query_one("#add-error", Static).update(Text(error, style="red"))
            return
        self.dismiss(True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        else:
            self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class LootScreen(Screen[None]):
    BINDINGS = [
        Binding("a", "add", "Add loot"),
        Binding("e", "edit", "Edit"),
        Binding("d", "delete", "Delete"),
        Binding("v", "reveal", "Show/hide secrets"),
        Binding("c", "copy", "Copy"),
        Binding("m", "verified", "Mark cred works on..."),
        Binding("k", "cracked", "Set cracked value"),
        Binding("escape", "back", "Back"),
        Binding("question_mark", "app.toggle_help", "Keys"),
    ]

    def __init__(self, ws: Workspace) -> None:
        super().__init__()
        self.ws = ws
        self.reveal = False
        self._rows: dict[str, Finding] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            "Loot: users, credentials and hashes found on this box (a add, e edit, d delete)",
            classes="section",
        )
        yield DataTable(id="loot", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Loot: {self.ws.meta.name}"
        table: DataTable[Any] = self.query_one("#loot", DataTable)
        table.add_columns("Type", "Who", "Value", "Notes", "Found by")
        self.fill()
        table.focus()

    def fill(self) -> None:
        from cyberdeck.ui.tui.dashboard import finding_row

        table: DataTable[Any] = self.query_one("#loot", DataTable)
        keep = table.cursor_row
        table.clear()
        self._rows = {}
        for ftype in LOOT_TYPES:
            for f in services.list_findings(self.ws, ftype):
                key = f"{f.type.value}:{f.key}"
                self._rows[key] = f
                table.add_row(*finding_row(f, self.reveal), ", ".join(f.sources[:2]), key=key)
        if not table.row_count:
            table.add_row("", "Nothing yet", "", "", "", key="-")
        table.move_cursor(row=min(keep, table.row_count - 1))

    def _current(self) -> Finding | None:
        table: DataTable[Any] = self.query_one("#loot", DataTable)
        key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        return self._rows.get(key)

    def action_add(self) -> None:
        def save(ftype: FindingType, data: dict[str, Any]) -> str | None:
            try:
                services.add_finding(self.ws, ftype, data, source="user", confidence=1.0)
            except OptionError as exc:
                return _friendly(str(exc))
            return None

        def done(added: bool | None) -> None:
            if added:
                self.notify("Added. Next steps may suggest where to try it.")
                self.fill()

        self.app.push_screen(AddLootModal(save), done)

    def action_edit(self) -> None:
        f = self._current()
        if f is None:
            self.notify("Nothing to edit", severity="warning")
            return

        def save(ftype: FindingType, data: dict[str, Any]) -> str | None:
            try:
                services.edit_finding(self.ws, ftype, f.key, data)
            except OptionError as exc:
                return _friendly(str(exc))
            return None

        def done(saved: bool | None) -> None:
            if saved:
                self.notify("Saved")
                self.fill()

        self.app.push_screen(AddLootModal(save, editing=f), done)

    @work
    async def action_delete(self) -> None:
        f = self._current()
        if f is None:
            self.notify("Nothing to delete", severity="warning")
            return
        from cyberdeck.ui.tui.dashboard import finding_row

        _, who, value, *_ = finding_row(f, False)
        sure = await self.app.push_screen_wait(
            ConfirmModal(
                f"Delete this {f.type.value}: {who} {value}?".replace("  ", " "),
                "A tool that finds it again will add it back.",
                yes="Delete",
                no="Keep",
            )
        )
        if not sure:
            return
        try:
            services.delete_finding(self.ws, f.type, f.key)
        except OptionError as exc:
            self.notify(str(exc), severity="error")
            return
        self.notify(f"Deleted the {f.type.value}")
        self.fill()

    def action_reveal(self) -> None:
        self.reveal = not self.reveal
        self.fill()

    def action_copy(self) -> None:
        f = self._current()
        if f is None:
            return
        d = f.data
        value = {
            FindingType.USER: d.get("name"),
            FindingType.CREDENTIAL: d.get("secret"),
            FindingType.HASH: d.get("cracked") or d.get("value"),
        }.get(f.type)
        if value:
            self.app.copy_to_clipboard(str(value))
            self.notify("Copied to the clipboard")

    @work
    async def action_verified(self) -> None:
        f = self._current()
        if f is None or f.type is not FindingType.CREDENTIAL:
            self.notify("Pick a credential first", severity="warning")
            return
        where = await self.app.push_screen_wait(
            InputModal("Works on (ssh, smb, winrm, web login...)", "ssh")
        )
        if where:
            services.mark_credential_verified(self.ws, f.key, where.strip())
            self.notify(f"Marked as working on {where}")
            self.fill()

    @work
    async def action_cracked(self) -> None:
        f = self._current()
        if f is None or f.type is not FindingType.HASH:
            self.notify("Pick a hash first", severity="warning")
            return
        value = await self.app.push_screen_wait(
            InputModal("Cracked value", password=not self.reveal)
        )
        if value:
            try:
                services.set_hash_cracked(self.ws, f.key, value)
            except OptionError as exc:
                self.notify(str(exc), severity="error")
                return
            self.notify("Saved the cracked value")
            self.fill()

    def action_back(self) -> None:
        self.app.pop_screen()


def _friendly(message: str) -> str:
    """Pydantic's validation text, shortened to what a person needs to fix."""
    if "hashcat_mode" in message:
        return "Hashcat mode must be a number"
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    if not lines:
        return "Could not save it"
    detail = next((line for line in lines[1:] if not line.startswith("For further")), "")
    return f"{lines[0]}: {detail}" if detail else lines[0]
