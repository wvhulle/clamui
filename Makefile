PREFIX ?= /usr/local
DESTDIR ?=
CARGO ?= cargo

APPLICATION_ID := page.codeberg.wvhulle.Lazaret
TRANSLATION_DOMAIN := lazaret
RELEASE_BINARY := target/release/lazaret
RELEASE_HELPER_BINARY := target/release/lazaret-settings-helper
HELPER_BUS_NAME := $(APPLICATION_ID).SettingsHelper
SYSCONFDIR ?= /etc
COMPILE_SCHEMAS ?= yes
INSTALL_ROOT := $(DESTDIR)$(PREFIX)
SHARE_DIRECTORY := $(INSTALL_ROOT)/share
HELPER_DIRECTORY := $(PREFIX)/libexec/lazaret
CONFIG_ROOT := $(DESTDIR)$(SYSCONFDIR)
TRANSLATION_BUILD_DIRECTORY ?= target/locale
SOURCE_FILES := $(shell find src -name '*.rs' | LC_ALL=C sort)
LINGUAS := $(shell sed -e '/^[[:space:]]*$$/d' -e '/^\#/d' po/LINGUAS)

.PHONY: build install install-binary install-data install-metainfo install-settings-helper install-user-service install-desktop-entry install-icons install-settings-schema install-translations compile-translations update-translation-template

build:
	$(CARGO) build --release --locked --package lazaret --package lazaret-settings-helper

install: install-binary install-data install-settings-helper

install-binary:
	install -Dm755 $(RELEASE_BINARY) $(INSTALL_ROOT)/bin/lazaret

install-data: install-desktop-entry install-metainfo install-icons install-settings-schema install-translations install-user-service

install-metainfo:
	install -Dm644 data/$(APPLICATION_ID).metainfo.xml.in $(SHARE_DIRECTORY)/metainfo/$(APPLICATION_ID).metainfo.xml

install-settings-helper:
	install -Dm755 $(RELEASE_HELPER_BINARY) $(DESTDIR)$(HELPER_DIRECTORY)/lazaret-settings-helper
	install -Dm644 data/$(APPLICATION_ID).policy $(SHARE_DIRECTORY)/polkit-1/actions/$(APPLICATION_ID).policy
	install -Dm644 data/$(APPLICATION_ID).SettingsHelper.conf $(SHARE_DIRECTORY)/dbus-1/system.d/$(HELPER_BUS_NAME).conf
	install -Dm644 data/$(APPLICATION_ID).SettingsHelper.service $(SHARE_DIRECTORY)/dbus-1/system-services/$(HELPER_BUS_NAME).service
	install -d $(INSTALL_ROOT)/lib/systemd/system
	sed 's|@HELPER_PATH@|$(HELPER_DIRECTORY)/lazaret-settings-helper|' data/lazaret-settings-helper.service.in > $(INSTALL_ROOT)/lib/systemd/system/lazaret-settings-helper.service
	sed 's|@HELPER_PATH@|$(HELPER_DIRECTORY)/lazaret-settings-helper|' data/lazaret-settings-merge.service.in > $(INSTALL_ROOT)/lib/systemd/system/lazaret-settings-merge.service
	install -Dm644 data/clamav-daemon-live-tuning.conf $(SHARE_DIRECTORY)/lazaret/clamav-daemon-live-tuning.conf
	install -d $(CONFIG_ROOT)/lazaret
	test -e $(CONFIG_ROOT)/lazaret/tunable-settings || install -m644 /dev/null $(CONFIG_ROOT)/lazaret/tunable-settings

install-user-service:
	install -d $(INSTALL_ROOT)/lib/systemd/user
	sed 's|@BINARY_PATH@|$(PREFIX)/bin/lazaret|' data/lazaret.service.in > $(INSTALL_ROOT)/lib/systemd/user/lazaret.service

install-desktop-entry:
	install -Dm644 data/$(APPLICATION_ID).desktop.in $(SHARE_DIRECTORY)/applications/$(APPLICATION_ID).desktop

install-icons:
	install -Dm644 data/icons/hicolor/scalable/apps/$(APPLICATION_ID).svg $(SHARE_DIRECTORY)/icons/hicolor/scalable/apps/$(APPLICATION_ID).svg

install-settings-schema:
	install -Dm644 data/$(APPLICATION_ID).gschema.xml $(SHARE_DIRECTORY)/glib-2.0/schemas/$(APPLICATION_ID).gschema.xml
	test "$(COMPILE_SCHEMAS)" != yes || glib-compile-schemas $(SHARE_DIRECTORY)/glib-2.0/schemas

update-translation-template:
	xgettext --language=Rust --from-code=UTF-8 --keyword=gettext --keyword=ngettext:1,2 \
		--package-name=$(TRANSLATION_DOMAIN) -o po/$(TRANSLATION_DOMAIN).pot $(SOURCE_FILES)

compile-translations:
	@$(foreach language,$(LINGUAS),\
		install -d $(TRANSLATION_BUILD_DIRECTORY)/$(language)/LC_MESSAGES && \
		msgfmt -o $(TRANSLATION_BUILD_DIRECTORY)/$(language)/LC_MESSAGES/$(TRANSLATION_DOMAIN).mo po/$(language).po &&) true

install-translations: compile-translations
	@$(foreach language,$(LINGUAS),\
		install -Dm644 $(TRANSLATION_BUILD_DIRECTORY)/$(language)/LC_MESSAGES/$(TRANSLATION_DOMAIN).mo \
			$(SHARE_DIRECTORY)/locale/$(language)/LC_MESSAGES/$(TRANSLATION_DOMAIN).mo &&) true
