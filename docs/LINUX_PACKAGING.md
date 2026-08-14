# Linux packaging

SafeChat's primary Linux distribution format is Flatpak. It bundles the
desktop runtime and avoids requiring users to install host libraries such as
Fontconfig, so the same package can run on Silverblue, Fedora, Ubuntu, and
other distributions with Flatpak support.

Build and install a local development package from the repository root:

```sh
flatpak install flathub org.flatpak.Builder
flatpak run org.flatpak.Builder --user --install --force-clean \
  packaging/flatpak/build \
  packaging/flatpak/io.safechat.SafeChat.yml
flatpak run io.safechat.SafeChat
```

At startup, select a saved profile or choose **Create new profile**. Each
profile has its own encrypted identity database. Multiple local clients can
run at the same time by launching the application twice and selecting a
different profile in each window.

```sh
flatpak run io.safechat.SafeChat
flatpak run io.safechat.SafeChat
```

Use separate terminal windows for the two commands. Create different display
names and passwords in each window; do not reuse an identity database when
testing two users.

The selected profile name is shown in the application header. Flatpak stores
these profiles under `~/.var/app/io.safechat.SafeChat/data/safechat/`.

The manifest currently permits network access during the Cargo dependency
build. Release CI should vendor or prefetch Cargo sources and remove that
permission before publishing artifacts. The Flatpak packages the current UI
prototype; it does not imply that all client features are complete.

AppImage can be added as a secondary single-file download for users who do
not want Flatpak. Native `.deb` and `.rpm` packages are less portable because
they intentionally rely on distribution-managed GUI libraries.

Tagged releases build a `.flatpak` bundle automatically in GitHub Actions and
attach it to the GitHub release alongside the native archives. Users can
install such a bundle with:

```sh
flatpak install --user ./safechat-<version>.flatpak
flatpak run io.safechat.SafeChat
```
