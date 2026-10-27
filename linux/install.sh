#!/bin/sh
# Installs cljpass for the current user on Linux (KDE Plasma, GNOME, ...):
#   program      ~/.local/lib/cljpass/        (native binary or cljpass.jar)
#   command      ~/.local/bin/cljpass
#   menu entry   ~/.local/share/applications/cljpass.desktop
#   icon         ~/.local/share/icons/hicolor/{scalable,NxN}/apps/cljpass.*
#   desktop      <XDG desktop dir>/cljpass.desktop   (unless --no-desktop-icon)
#
#   linux/install.sh                 install (builds target/cljpass.jar if nothing is built)
#   linux/install.sh --no-desktop-icon
#   linux/install.sh --uninstall     remove everything above (the vault data in
#                                    ~/.local/share/cljpass is kept)
#
# Prefers the native binary target/cljpass (clojure -T:build native); otherwise
# installs target/cljpass.jar with a launcher that uses a Java 21+ found now.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
data=${XDG_DATA_HOME:-$HOME/.local/share}
lib=$HOME/.local/lib/cljpass
bin=$HOME/.local/bin
apps=$data/applications
icons=$data/icons/hicolor
desktop_dir=$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")

desktop_icon=1
uninstall=0
for a in "$@"; do
  case $a in
    --no-desktop-icon) desktop_icon=0 ;;
    --uninstall) uninstall=1 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

refresh() {
  update-desktop-database -q "$apps" 2>/dev/null || true
  [ -d "$icons" ] && { touch "$icons"; gtk-update-icon-cache -q -f -t "$icons" 2>/dev/null || true; }
  # KDE Plasma: rebuild the menu cache so the entry appears immediately
  for k in kbuildsycoca6 kbuildsycoca5; do
    command -v $k >/dev/null 2>&1 && { $k >/dev/null 2>&1 || true; break; }
  done
}

if [ $uninstall = 1 ]; then
  rm -rf "$lib"
  rm -f "$bin/cljpass" "$apps/cljpass.desktop" "$desktop_dir/cljpass.desktop"
  rm -f "$icons"/*/apps/cljpass.png "$icons/scalable/apps/cljpass.svg"
  refresh
  echo "cljpass removed (data in $data/cljpass kept)."
  exit 0
fi

# ---------------------------------------------------------------- program

java_ok() { # $1 = java executable; true for Java 21+ that can load the system GTK
  # Homebrew/Linuxbrew builds use their own ld.so and do not find the system's
  # libgtk-3 -> SWT fails with UnsatisfiedLinkError
  case $(readlink -f "$1") in */linuxbrew/*|*/.linuxbrew/*) return 1 ;; esac
  v=$("$1" -XshowSettings:properties -version 2>&1 | sed -n 's/^ *java.specification.version = //p')
  [ -n "$v" ] && [ "${v%%.*}" -ge 21 ] 2>/dev/null
}

find_java() {
  for j in ${JAVA_HOME:+"$JAVA_HOME/bin/java"} "$(command -v java 2>/dev/null)" \
           /usr/lib/jvm/*/bin/java /usr/bin/jdk-*/bin/java /opt/*/bin/java; do
    [ -n "$j" ] && [ -x "$j" ] && java_ok "$j" && { echo "$j"; return; }
  done
  return 1
}

mkdir -p "$lib" "$bin" "$apps"
rm -f "$bin/cljpass"

# GTK_USE_PORTAL=1: SWT's GtkFileChooserNative goes through xdg-desktop-portal,
# i.e. the desktop's own file dialog (KDE: Dolphin-style with all places, /mnt,
# network). Without a portal GTK falls back to its own dialog.
portal_env='[ -n "${GTK_USE_PORTAL:-}" ] || export GTK_USE_PORTAL=1'

if [ -f "$root/target/cljpass" ] && [ -x "$root/target/cljpass" ]; then
  install -m 755 "$root/target/cljpass" "$lib/cljpass"
  rm -f "$lib/cljpass.jar"
  cat > "$lib/cljpass.sh" <<EOF
#!/bin/sh
$portal_env
exec "$lib/cljpass" "\$@"
EOF
  chmod 755 "$lib/cljpass.sh"
  ln -s "$lib/cljpass.sh" "$bin/cljpass"
  kind="native binary"
else
  if [ ! -f "$root/target/cljpass.jar" ]; then
    echo "Building target/cljpass.jar ..."
    (cd "$root" && clojure -T:build uber)
  fi
  java=$(find_java) || { echo "No Java 21 or newer found (set JAVA_HOME; Homebrew Java cannot load GTK)." >&2; exit 1; }
  install -m 644 "$root/target/cljpass.jar" "$lib/cljpass.jar"
  rm -f "$lib/cljpass"
  # absolute Java path: menu and desktop start without the shell's PATH
  cat > "$lib/cljpass.sh" <<EOF
#!/bin/sh
$portal_env
exec "$java" --enable-native-access=ALL-UNNAMED -jar "$lib/cljpass.jar" "\$@"
EOF
  chmod 755 "$lib/cljpass.sh"
  ln -s "$lib/cljpass.sh" "$bin/cljpass"
  kind="cljpass.jar with $java"
fi

# ---------------------------------------------------------------- icon

install -D -m 644 "$here/cljpass.svg" "$icons/scalable/apps/cljpass.svg"
# raster sizes for panels/tools that do not render SVG
if command -v rsvg-convert >/dev/null 2>&1 || command -v inkscape >/dev/null 2>&1; then
  for s in 16 22 24 32 48 64 128 256; do
    out="$icons/${s}x${s}/apps/cljpass.png"
    mkdir -p "$(dirname "$out")"
    if command -v rsvg-convert >/dev/null 2>&1; then
      rsvg-convert -w $s -h $s -o "$out" "$here/cljpass.svg"
    else
      inkscape -w $s -h $s -o "$out" "$here/cljpass.svg" >/dev/null 2>&1
    fi
  done
fi

# ---------------------------------------------------------------- menu entry

# StartupWMClass = Display.setAppName "cljpass": taskbar and window get the icon
cat > "$apps/cljpass.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=cljpass
GenericName=Password Manager
GenericName[de]=Passwortverwaltung
Comment=Team password safe, compatible with KeePass
Comment[de]=Team-Passwortspeicher, kompatibel mit KeePass
Exec=$bin/cljpass
TryExec=$bin/cljpass
Icon=cljpass
Terminal=false
StartupNotify=true
StartupWMClass=cljpass
Categories=Utility;Security;
Keywords=password;keepass;kdbx;vault;Passwort;Tresor;
EOF
command -v desktop-file-validate >/dev/null 2>&1 && desktop-file-validate --no-hints "$apps/cljpass.desktop"

# ---------------------------------------------------------------- desktop icon

if [ $desktop_icon = 1 ] && [ -d "$desktop_dir" ]; then
  install -m 755 "$apps/cljpass.desktop" "$desktop_dir/cljpass.desktop"
  # GNOME/Nautilus-style trust flag (KDE uses the executable bit)
  command -v gio >/dev/null 2>&1 && gio set "$desktop_dir/cljpass.desktop" metadata::trusted true 2>/dev/null || true
fi

refresh

echo "cljpass installed ($kind)."
echo "  menu:    Utilities / Security -> cljpass"
[ $desktop_icon = 1 ] && echo "  desktop: $desktop_dir/cljpass.desktop"
case ":$PATH:" in *":$bin:"*) ;; *) echo "  note: $bin is not on PATH" ;; esac
