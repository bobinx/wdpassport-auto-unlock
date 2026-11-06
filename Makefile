PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
SYSTEMD_SYSTEM_DIR ?= /etc/systemd/system
UDEV_RULES_DIR ?= /etc/udev/rules.d
GO ?= go
CGO_ENABLED ?= 0
LDFLAGS ?= -s -w

.PHONY: all build deb test install uninstall clean

all: build

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags="$(LDFLAGS)" -o wd-auto-unlock ./cmd/wd-auto-unlock

deb:
	$(GO) run ./cmd/build-deb amd64
	$(GO) run ./cmd/build-deb arm64

test:
	$(GO) test -v ./...

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 wd-auto-unlock $(DESTDIR)$(BINDIR)/wd-auto-unlock
	install -d $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)
	sed 's|/usr/local/bin|$(BINDIR)|g' wd-unlock.service > $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/wd-unlock.service
	chmod 0644 $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/wd-unlock.service
	install -m 0644 wd-unlock.timer $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/wd-unlock.timer
	install -d $(DESTDIR)$(UDEV_RULES_DIR)
	install -m 0644 99-wd-passport.rules $(DESTDIR)$(UDEV_RULES_DIR)/99-wd-passport.rules
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/wdpassport.conf ]; then \
		install -d $(DESTDIR)$(SYSCONFDIR); \
		install -m 0600 wdpassport.conf.example $(DESTDIR)$(SYSCONFDIR)/wdpassport.conf; \
		echo "Installed sample configuration to $(DESTDIR)$(SYSCONFDIR)/wdpassport.conf"; \
	fi
	@echo "Installation complete."

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/wd-auto-unlock
	rm -f $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/wd-unlock.service
	rm -f $(DESTDIR)$(SYSTEMD_SYSTEM_DIR)/wd-unlock.timer
	rm -f $(DESTDIR)$(UDEV_RULES_DIR)/99-wd-passport.rules
	@echo "Uninstalled binaries and systemd units."
	@echo "Note: $(DESTDIR)$(SYSCONFDIR)/wdpassport.conf was preserved."

clean:
	rm -f wd-auto-unlock
	rm -rf dist
