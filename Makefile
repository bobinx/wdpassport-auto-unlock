PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
SYSTEMD_SYSTEM_DIR ?= /etc/systemd/system
UDEV_RULES_DIR ?= /etc/udev/rules.d
PYTHON ?= python3

.PHONY: all lint install uninstall clean

all:
	@echo "wd-auto-unlock is a zero-dependency Python utility."
	@echo "Run 'make lint' to check syntax, or 'sudo make install' to install."

lint:
	$(PYTHON) -m py_compile wd_auto_unlock.py

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 wd_auto_unlock.py $(DESTDIR)$(BINDIR)/wd-auto-unlock
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
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.py[cod]" -delete 2>/dev/null || true
	rm -rf .coverage .pytest_cache .mypy_cache
