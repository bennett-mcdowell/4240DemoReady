from dataclasses import dataclass, field
from pathlib import Path
import json
import logging
import tempfile
import os

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("/etc/sshguard-dashboard/config.json")


class ConfigError(Exception):

    pass


@dataclass
class Config:

    threshold: int = 5
    window_seconds: int = 300
    log_path: str = "/var/log/auth.log"
    whitelist: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    _config_path: str | Path = field(default=DEFAULT_CONFIG_PATH)

    def validate(self) -> None:
        if self.threshold < 1:
            raise ConfigError(f"threshold must be >= 1, got {self.threshold}")
        if self.window_seconds < 1:
            raise ConfigError(f"window_seconds must be >= 1, got {self.window_seconds}")

    def reload(self) -> bool:
        path = Path(self._config_path)

        if not path.exists():
            logger.error(f"Config file not found: {self._config_path}")
            return False

        try:
            with open(path, "r") as f:
                data = json.load(f)

            new_config = Config(
                threshold=data.get("threshold", DEFAULT_CONFIG.threshold),
                window_seconds=data.get("window_seconds", DEFAULT_CONFIG.window_seconds),
                log_path=data.get("log_path", DEFAULT_CONFIG.log_path),
                whitelist=data.get("whitelist", DEFAULT_CONFIG.whitelist.copy()),
                _config_path=path
            )

            new_config.validate()

            self.threshold = new_config.threshold
            self.window_seconds = new_config.window_seconds
            self.log_path = new_config.log_path
            self.whitelist = new_config.whitelist

            logger.info(f"Config reloaded: threshold={self.threshold}, window={self.window_seconds}s")
            return True

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return False
        except ConfigError as e:
            logger.error(f"Invalid config values: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to reload config: {e}")
            return False


DEFAULT_CONFIG = Config()


def save_config(config: Config, config_path: Path | str | None = None) -> None:
    config.validate()

    path = Path(config_path) if config_path else Path(config._config_path)

    data = {
        "threshold": config.threshold,
        "window_seconds": config.window_seconds,
        "log_path": config.log_path,
        "whitelist": config.whitelist
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode='w',
        dir=path.parent,
        delete=False,
        suffix='.tmp'
    ) as tmp_file:
        json.dump(data, tmp_file, indent=2)
        tmp_name = tmp_file.name

    try:
        os.replace(tmp_name, path)
        logger.info(f"Config saved to {path}")
    except Exception as e:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise IOError(f"Failed to save config to {path}: {e}")


def load_config(config_path: Path | str | None = None) -> Config:
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if not path.exists():
        logger.info(f"Config file {path} not found, using defaults")
        return DEFAULT_CONFIG

    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON in {path}: {e}")

    config = Config(
        threshold=data.get("threshold", DEFAULT_CONFIG.threshold),
        window_seconds=data.get("window_seconds", DEFAULT_CONFIG.window_seconds),
        log_path=data.get("log_path", DEFAULT_CONFIG.log_path),
        whitelist=data.get("whitelist", DEFAULT_CONFIG.whitelist.copy()),
        _config_path=path
    )
    config.validate()
    return config
