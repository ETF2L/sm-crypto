#!/usr/bin/env python3
# Copyright 2026 ETF2L Contributors, Dave
#
# Builds smcrypto.ext.dll for x86 and x64 on Windows with Visual Studio
# 2022 (or the Build Tools) and runs the unit tests of both:
#
#   python windows\build.py --work C:\path\to\work --out C:\path\to\out
#
# Into the work directory it fetches what the build needs, and again when a
# pin moved: vcpkg at the commit vcpkg\vcpkg.json pins, SourceMod's headers
# and AMBuild (in a virtual environment of its own) at the commits
# toolchain.json pins. It builds Mbed TLS with the triplets of
# vcpkg\triplets\ (static libraries, static runtime /MT), configures one
# AMBuild build per architecture inside that architecture's MSVC
# environment, runs the unit tests, checks that each DLL exports only
# GetSMExtAPI and needs no runtime DLL, and copies the DLLs to
# <out>\extensions\ and <out>\extensions\x64\. Needs git and Python 3.8+.
import argparse
import json
import os
import shutil
import string
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VCPKG_URL = 'https://github.com/microsoft/vcpkg'
SOURCEMOD_URL = 'https://github.com/alliedmodders/sourcemod'
AMBUILD_URL = 'git+https://github.com/alliedmodders/ambuild'
VSWHERE = os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                       'Microsoft Visual Studio', 'Installer', 'vswhere.exe')
# (vcvarsall argument, AMBuild target, vcpkg triplet, library folder)
ARCHITECTURES = [
  ('x86', 'x86', 'x86-windows-smcrypto', 'x86'),
  ('x64', 'x86_64', 'x64-windows-smcrypto', 'x64'),
]
# What the DLL may load besides itself: Windows' own libraries only.
ALLOWED_DLLS = {'kernel32.dll', 'user32.dll', 'advapi32.dll', 'bcrypt.dll'}


def run(command, **kwargs):
  print('>', ' '.join(command), flush=True)
  subprocess.run(command, check=True, **kwargs)


def output_of(command, **kwargs):
  return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs).stdout


def fail(message):
  sys.exit('build.py: ' + message)


def pinned_vcpkg_commit():
  with open(os.path.join(ROOT, 'vcpkg', 'vcpkg.json')) as manifest:
    return json.load(manifest)['builtin-baseline']


def pinned_toolchain_commit(name):
  with open(os.path.join(ROOT, 'toolchain.json')) as pins:
    return json.load(pins)[name]


def head_of(repository):
  return subprocess.run(['git', '-C', repository, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()


def fetch_vcpkg(work):
  vcpkg = os.path.join(work, 'vcpkg')
  commit = pinned_vcpkg_commit()
  if not os.path.isdir(os.path.join(vcpkg, '.git')):
    run(['git', 'init', '-q', vcpkg])
  if head_of(vcpkg) != commit:
    run(['git', '-C', vcpkg, 'fetch', '-q', '--depth', '1', VCPKG_URL, commit])
    run(['git', '-C', vcpkg, 'checkout', '-q', 'FETCH_HEAD'])
    executable = os.path.join(vcpkg, 'vcpkg.exe')
    if os.path.exists(executable):
      os.remove(executable)
  if not os.path.exists(os.path.join(vcpkg, 'vcpkg.exe')):
    run([os.path.join(vcpkg, 'bootstrap-vcpkg.bat'), '-disableMetrics'])
  return vcpkg


def fetch_sourcemod(work):
  sourcemod = os.path.join(work, 'sourcemod')
  commit = pinned_toolchain_commit('sourcemod')
  if not os.path.isdir(os.path.join(sourcemod, '.git')):
    run(['git', 'init', '-q', sourcemod])
  if head_of(sourcemod) != commit:
    run(['git', '-C', sourcemod, 'fetch', '-q', '--depth', '1', SOURCEMOD_URL, commit])
    run(['git', '-C', sourcemod, 'checkout', '-q', 'FETCH_HEAD'])
  # Every run, so a run stopped after the checkout cannot leave old submodules.
  run(['git', '-C', sourcemod, 'submodule', 'update', '-q', '--init', '--recursive', '--depth', '1'])
  return sourcemod


def fetch_ambuild(work):
  venv = os.path.join(work, 'venv')
  python = os.path.join(venv, 'Scripts', 'python.exe')
  if not os.path.exists(python):
    run([sys.executable, '-m', 'venv', venv])
  pinned = '{}@{}'.format(AMBUILD_URL, pinned_toolchain_commit('ambuild'))
  installed = output_of([python, '-m', 'pip', 'freeze'])
  if pinned not in installed:
    run([python, '-m', 'pip', 'install', '-q', '--force-reinstall', pinned])
  return python


def build_libraries(vcpkg, work):
  libs = os.path.join(work, 'libs')
  for _, _, triplet, folder in ARCHITECTURES:
    installed = os.path.join(work, 'vcpkg_installed-' + folder)
    run([os.path.join(vcpkg, 'vcpkg.exe'), 'install', '--x-manifest-root=' + os.path.join(ROOT, 'vcpkg'),
         '--triplet', triplet, '--x-install-root=' + installed, '--clean-after-build'])
    target = os.path.join(libs, folder)
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(os.path.join(installed, triplet), target)
  return libs


def msvc_environment(vcvars_arch):
  if not os.path.exists(VSWHERE):
    fail('vswhere.exe not found: install Visual Studio 2022 or its Build Tools')
  installation = output_of([VSWHERE, '-latest', '-products', '*', '-requires',
                            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property',
                            'installationPath']).strip()
  if not installation:
    fail('no Visual Studio with the C++ tools found')
  vcvarsall = os.path.join(installation, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat')
  dump = output_of('cmd /s /c ""{}" {} >nul && set"'.format(vcvarsall, vcvars_arch), shell=True)
  environment = {}
  for line in dump.splitlines():
    name, separator, value = line.partition('=')
    if separator:
      environment[name] = value
  return environment


def build_architecture(work, python, sourcemod, libs, vcvars_arch, target):
  environment = msvc_environment(vcvars_arch)
  build = os.path.join(work, 'build-' + target)
  shutil.rmtree(build, ignore_errors=True)
  os.makedirs(build)
  run([python, os.path.join(ROOT, 'extension', 'configure.py'), '--enable-optimize', '--targets=' + target,
       '--sm-path=' + sourcemod, '--libs-path=' + libs], cwd=build, env=environment)
  run([os.path.join(os.path.dirname(python), 'ambuild.exe')], cwd=build, env=environment)
  platform = 'windows-' + target
  tests = os.path.join(build, 'tests', 'smcrypto-tests-' + target, platform, 'smcrypto-tests-' + target + '.exe')
  run([tests], cwd=build, env=environment)
  dll = os.path.join(build, 'smcrypto.ext', platform, 'smcrypto.ext.dll')
  check_dll(dll, environment)
  return dll


# A row of dumpbin's export table: ordinal, hint, RVA (hex), name, and for
# x86 "= <decorated name>".
def is_export_row(fields):
  is_hex = lambda text: all(character in string.hexdigits for character in text)
  return len(fields) >= 4 and fields[0].isdigit() and is_hex(fields[1]) and len(fields[2]) >= 8 and is_hex(fields[2])


# The path of a tool of the MSVC environment: Windows looks a program up in
# the PATH of the calling process, not in the one it is given.
def msvc_tool(environment, name):
  path = next((value for key, value in environment.items() if key.upper() == 'PATH'), '')
  found = shutil.which(name, path=path)
  if not found:
    fail('{} not found in the MSVC environment'.format(name))
  return found


def check_dll(dll, environment):
  dumpbin = msvc_tool(environment, 'dumpbin.exe')
  exports = output_of([dumpbin, '/nologo', '/exports', dll], env=environment)
  names = [fields[3] for fields in (line.split() for line in exports.splitlines()) if is_export_row(fields)]
  if names != ['GetSMExtAPI']:
    fail('{} exports {}'.format(dll, names))
  dependents = output_of([dumpbin, '/nologo', '/dependents', dll], env=environment)
  # The dependencies are listed one name per line.
  needed = {line.strip().lower() for line in dependents.splitlines()
            if len(line.split()) == 1 and line.strip().lower().endswith('.dll')}
  if not needed <= ALLOWED_DLLS:
    fail('{} needs {}'.format(dll, sorted(needed - ALLOWED_DLLS)))
  print('{}: exports GetSMExtAPI, needs {}'.format(dll, ', '.join(sorted(needed))), flush=True)


def main():
  parser = argparse.ArgumentParser(description='Builds smcrypto.ext.dll for x86 and x64.')
  parser.add_argument('--work', required=True, help='work directory for the fetched tools and the builds')
  parser.add_argument('--out', required=True, help='where extensions\\ with the DLLs is written')
  arguments = parser.parse_args()
  work = os.path.abspath(arguments.work)
  os.makedirs(work, exist_ok=True)

  vcpkg = fetch_vcpkg(work)
  sourcemod = fetch_sourcemod(work)
  python = fetch_ambuild(work)
  libs = build_libraries(vcpkg, work)

  out = os.path.join(os.path.abspath(arguments.out), 'extensions')
  shutil.rmtree(out, ignore_errors=True)
  for vcvars_arch, target, _, folder in ARCHITECTURES:
    dll = build_architecture(work, python, sourcemod, libs, vcvars_arch, target)
    destination = out if folder == 'x86' else os.path.join(out, 'x64')
    os.makedirs(destination, exist_ok=True)
    shutil.copy2(dll, destination)
  print('Built', out, flush=True)


if __name__ == '__main__':
  main()
