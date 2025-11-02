try:
    from .cli import main
except ImportError:  # pragma: no cover - fallback for frozen builds
    from glitter.cli import main  # type: ignore[import] - accessible in PyInstaller bundle

if __name__ == "__main__":
    raise SystemExit(main())
