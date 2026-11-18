# SPDX-License-Identifier: MIT
# nano is the installed editor; tools fall back to a missing vi without this.
[ -n "${EDITOR-}" ] || export EDITOR=nano
