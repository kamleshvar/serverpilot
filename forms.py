"""WTForms definitions with CSRF protection built in."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, NumberRange, Optional, Regexp


class AdminLoginForm(FlaskForm):
    passcode = PasswordField(
        "Administrator passcode",
        validators=[DataRequired(), Length(min=1, max=512)],
        render_kw={"autocomplete": "current-password", "autofocus": True},
    )
    submit = SubmitField("Sign in to administration")


class ServerAddForm(FlaskForm):
    name = StringField(
        "Server name",
        validators=[DataRequired(), Length(min=1, max=120)],
        render_kw={"placeholder": "app-server-1"},
    )
    hostname = StringField(
        "IP address or hostname",
        validators=[DataRequired(), Length(min=1, max=253)],
        render_kw={
            "placeholder": "203.0.113.10 or app1.example.com",
            "autocapitalize": "none",
        },
    )
    ssh_port = IntegerField(
        "SSH port",
        validators=[DataRequired(), NumberRange(min=1, max=65535)],
        default=22,
    )
    ssh_username = StringField(
        "SSH username",
        validators=[DataRequired(), Length(min=1, max=32)],
        default="ubuntu",
        render_kw={"autocomplete": "username", "autocapitalize": "none"},
    )
    auth_method = SelectField(
        "SSH authentication method",
        choices=[("private_key", "SSH private key")],
        validators=[DataRequired()],
        default="private_key",
    )
    private_key = TextAreaField(
        "SSH private key",
        validators=[DataRequired(), Length(min=32, max=32768)],
        render_kw={
            "rows": 9,
            "placeholder": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "autocomplete": "off",
            "spellcheck": "false",
            "class": "admin-mono-input",
        },
    )
    key_passphrase = PasswordField(
        "Private key passphrase (optional)",
        validators=[Optional(), Length(max=1024)],
        render_kw={"autocomplete": "new-password"},
    )
    host_key_fingerprint = StringField(
        "SSH host key fingerprint (SHA256)",
        validators=[Optional(), Length(max=255)],
        render_kw={"placeholder": "SHA256:...", "autocomplete": "off"},
    )
    sudo_password = PasswordField(
        "sudo password (optional, only if required)",
        validators=[Optional(), Length(max=1024)],
        render_kw={"autocomplete": "new-password"},
    )
    auto_scan = BooleanField(
        "Scan the server automatically after connecting", default=True
    )
    install_agent = BooleanField(
        "Install the ServerPilot Agent after the scan", default=False
    )
    submit = SubmitField("Connect and scan server")


class ServerRescanForm(FlaskForm):
    private_key = TextAreaField(
        "SSH private key",
        validators=[DataRequired(), Length(min=32, max=32768)],
        render_kw={
            "rows": 6,
            "placeholder": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "autocomplete": "off",
            "spellcheck": "false",
        },
    )
    key_passphrase = PasswordField(
        "Private key passphrase (optional)",
        validators=[Optional(), Length(max=1024)],
        render_kw={"autocomplete": "new-password"},
    )
    host_key_fingerprint = StringField(
        "SSH host key fingerprint (SHA256)",
        validators=[Optional(), Length(max=255)],
        render_kw={
            "placeholder": "Leave blank to use the stored fingerprint",
            "autocomplete": "off",
        },
    )
    sudo_password = PasswordField(
        "sudo password (optional)",
        validators=[Optional(), Length(max=1024)],
        render_kw={"autocomplete": "new-password"},
    )
    install_agent = BooleanField(
        "Install the ServerPilot Agent after rescanning", default=False
    )
    submit = SubmitField("Reconnect and scan")


class WebsiteForm(FlaskForm):
    name = StringField(
        "Website name",
        validators=[DataRequired(), Length(min=1, max=120)],
        render_kw={"placeholder": "Customer portal"},
    )
    subdomain = StringField(
        "Subdomain",
        validators=[
            DataRequired(),
            Length(min=1, max=63),
            Regexp(
                r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
                message="Use lowercase letters, numbers and hyphens only.",
            ),
        ],
        render_kw={"placeholder": "customer-portal", "autocapitalize": "none"},
    )
    domain_name = SelectField("Domain", validators=[DataRequired()])
    repository_full_name = StringField(
        "GitHub repository",
        validators=[DataRequired(), Length(min=3, max=255)],
        render_kw={"placeholder": "owner/repository", "list": "repository-options"},
    )
    branch = StringField(
        "Branch",
        validators=[DataRequired(), Length(min=1, max=255)],
        default="main",
        render_kw={"placeholder": "main"},
    )
    framework = SelectField(
        "Framework",
        validators=[DataRequired()],
        choices=[
            ("flask", "Flask"),
            ("python", "Python"),
            ("node", "Node.js"),
            ("static", "Static site"),
            ("other", "Other"),
        ],
        default="flask",
    )
    root_directory = StringField(
        "Root directory",
        validators=[Optional(), Length(max=255)],
        render_kw={"placeholder": "Optional, for monorepos"},
    )
    build_command = StringField(
        "Build command",
        validators=[Optional(), Length(max=4000)],
        render_kw={"placeholder": "pip install -r requirements.txt"},
    )
    start_command = StringField(
        "Start command",
        validators=[Optional(), Length(max=4000)],
        render_kw={
            "placeholder": "Leave empty to auto-detect (e.g. gunicorn app:app --bind 0.0.0.0:8000)"
        },
    )
    internal_port = IntegerField(
        "Internal port",
        validators=[DataRequired(), NumberRange(min=1, max=65535)],
        default=8000,
    )
    healthcheck_path = StringField(
        "Health check path",
        validators=[DataRequired(), Length(max=255), Regexp(r"^/\S*$")],
        default="/",
    )
    auto_deploy_enabled = BooleanField("Deploy automatically on pushes to this branch")
    submit = SubmitField("Create website")
