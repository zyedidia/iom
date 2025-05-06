project('iom', ['c'], default_options: ['warning_level=3', 'buildtype=release'])

subdir('src')

capstone = subproject('capstone', default_options: ['default_library=static', 'warning_level=1']).get_variable('capstone_dep')
libelf = subproject('libelf').get_variable('libelf_dep')
argtable = subproject('argtable3').get_variable('argtable_dep')

executable(
  'iom',
  srcs,
  dependencies: [libelf, capstone, argtable],
)
