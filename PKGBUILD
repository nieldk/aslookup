# Maintainer: Your Name <your@email.com>
pkgname=aslookup
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url="https://github.com/nieldk/aslookup"
license=('GPL')
depends=('curl' 'cjson')
source=("$pkgname.c")
sha256sums=('SKIP')

build() {
  gcc $pkgname.c -o $pkgname -lcurl -lcjson -lresolv
}

package() {
  install -Dm755 $pkgname "$pkgdir/usr/bin/$pkgname"
}
