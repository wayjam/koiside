"""Finder layout. Used by dmgbuild, without Finder automation permissions."""
from pathlib import Path

application = Path(defines["app"]).resolve()
files = [str(application)]
symlinks = {"Applications": "/Applications"}
icon = str(application / "Contents/Resources/AppIcon.icns")
background = str(Path(defines["background"]).resolve())
format = "ULFO"
window_rect = ((200, 200), (640, 400))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
include_icon_view_settings = True
include_list_view_settings = False
icon_size = 112
text_size = 13
icon_locations = {application.name: (170, 180), "Applications": (470, 180)}
