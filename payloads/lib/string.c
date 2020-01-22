unsigned int strlen(const char *s) {
	unsigned int l = 0;
	while(*s != 0) {
		++l;
		++s;
	}
	return l;
}