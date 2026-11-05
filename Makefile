PREFIX ?= /usr/local
DESTDIR ?=
CARGO ?= cargo

APPLICATION_ID := io.github.wvhulle.ClamUI
TRANSLATION_DOMAIN := clamui
RELEASE_BINARY := target/release/clamui
INSTALL_ROOT := $(DESTDIR)$(PREFIX)
SHARE_DIRECTORY := $(INSTALL_ROOT)/share
TRANSLATION_BUILD_DIRECTORY ?= target/locale
SOURCE_FILES := $(shell find src -name '*.rs' | LC_ALL=C sort)
LINGUAS := $(shell sed -e '/^[[:space:]]*$$/d' -e '/^\#/d' po/LINGUAS)

.PHONY: build install install-binary install-data install-user-service install-desktop-entry install-icons install-settings-schema install-translations compile-translations update-translation-template

build:
	$(CARGO) build --release --locked

install: install-binary install-data

install-binary:
	install -Dm755 $(RELEASE_BINARY) $(INSTALL_ROOT)/bin/clamui

install-data: install-desktop-entry install-icons install-settings-schema install-translations install-user-service

install-user-service:
	install -d $(INSTALL_ROOT)/lib/systemd/user
	sed 's|@BINARY_PATH@|$(PREFIX)/bin/clamui|' data/clamui.service.in > $(INSTALL_ROOT)/lib/systemd/user/clamui.service

install-desktop-entry:
	install -Dm644 data/$(APPLICATION_ID).desktop.in $(SHARE_DIRECTORY)/applications/$(APPLICATION_ID).desktop

install-icons:
	install -Dm644 data/icons/hicolor/scalable/apps/$(APPLICATION_ID).svg $(SHARE_DIRECTORY)/icons/hicolor/scalable/apps/$(APPLICATION_ID).svg

install-settings-schema:
	install -Dm644 data/$(APPLICATION_ID).gschema.xml $(SHARE_DIRECTORY)/glib-2.0/schemas/$(APPLICATION_ID).gschema.xml
	glib-compile-schemas $(SHARE_DIRECTORY)/glib-2.0/schemas

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
