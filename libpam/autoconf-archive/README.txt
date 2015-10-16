
# This contains a few extra macros from the Autoconf Archive.
# It was populated with:

ACAVER=autoconf-archive-2015.09.25
[ -e "${ACAVER}.tar.xz" ] || \
curl -O "http://gnu.mirror.iweb.com/autoconf-archive/${ACAVER}".tar.xz
xz -c -d "${ACAVER}".tar.xz | tar xf -
M4FILES="
	ax_append_compile_flags.m4
	ax_append_flag.m4
	ax_check_compile_flag.m4
	ax_require_defined.m4
"

mkdir -p autoconf-archive/m4
for m in $M4FILES ; do
	cp "${ACAVER}/m4/$m" autoconf-archive/m4/.
done

git add autoconf-archive
