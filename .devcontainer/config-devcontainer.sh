#!/usr/bin/env bash

# The latest version of this script is in the OCI Images repo:
# https://github.com/NiceGuyIT/oci-images/blob/main/.devcontainer/config-devcontainer.sh

# FIXME: It seems JetBrains does not run postCreateCommand as the user.
# https://containers.dev/implementors/json_reference/
# This is run as root.

# Add the user to the host's docker group
sudoIf() { if [ "$(id -u)" -ne 0 ]; then sudo "$@"; else "$@"; fi }
NONROOT_USER=dev
NONROOT_GROUP=dev
SOCKET_GID=$(stat -c '%g' /var/run/docker.sock)
if [ "${SOCKET_GID}" != '0' ]; then
  if [ "$(grep :${SOCKET_GID}: /etc/group)" = '' ]; then
    sudoIf groupadd --gid ${SOCKET_GID} docker-host;
  fi

  if [ "$( id ${NONROOT_USER} | grep -E "groups=.*(=|,)${SOCKET_GID}\(" )" = '' ]; then
    sudoIf usermod --append --group ${SOCKET_GID} ${NONROOT_USER};
  fi
fi

# https://www.jetbrains.com/help/idea/dev-container-limitations.html#additional_limitations_remote_backend
# The following environment variables are used by the remote backend IDE and cannot be reassigned in the
# `devcontainer.json` configuration file:
#   XDG_CACHE_HOME
#   XDG_CONFIG_HOME
#   XDG_DATA_HOME
if [[ -d /.jbdevcontainer/ ]]
then

  # Chezmoi uses $XDG_CONFIG_HOME for the config directory and $XDG_DATA_HOME for the data directory.
  # If the persistent config doesn't exist, copy the container's config to it.
  program=chezmoi
  if [[ -d /.jbdevcontainer/config/ ]]
  then
    if [[ ! -e /.jbdevcontainer/config/${program} ]]
    then
      echo "Moving '/home/${NONROOT_USER}/.config/${program}' to '/.jbdevcontainer/config/'"
      sudoIf mv /home/${NONROOT_USER}/.config/${program} /.jbdevcontainer/config/
      sudoIf chown --recursive ${NONROOT_USER}:${NONROOT_GROUP} /.jbdevcontainer/config/${program}
    fi

    # The jbdevcontainer image exists but a new container image may not have the symlink in the home directory.
    # Remove the directory so the symlink below works.
    [[ -e /home/${NONROOT_USER}/.config/${program} ]] && rm -r /home/${NONROOT_USER}/.config/${program}
    [[ -L /home/${NONROOT_USER}/.config/${program} ]] && rm /home/${NONROOT_USER}/.config/${program}

    # Symlink the container's config to the persistent config.
    ln -s /.jbdevcontainer/config/${program} /home/${NONROOT_USER}/.config/${program}
    chown --no-dereference ${NONROOT_USER}:${NONROOT_GROUP} /home/${NONROOT_USER}/.config/${program}
  fi

  # Nushell uses $XDG_CONFIG_HOME for the config directory.
  program=nushell
  if [[ -d /.jbdevcontainer/config/ ]]
  then
    if [[ ! -e /.jbdevcontainer/config/${program} ]]
    then
      echo "Moving '/home/${NONROOT_USER}/.config/${program}' to '/.jbdevcontainer/config/'"
      sudoIf mv /home/${NONROOT_USER}/.config/${program} /.jbdevcontainer/config/
      sudoIf chown --recursive ${NONROOT_USER}:${NONROOT_GROUP} /.jbdevcontainer/config/${program}
    fi

    # The jbdevcontainer image exists but a new container image may not have the symlink in the home directory.
    # Remove the directory so the symlink below works.
    [[ -e /home/${NONROOT_USER}/.config/${program} ]] && rm -r /home/${NONROOT_USER}/.config/${program}
    [[ -L /home/${NONROOT_USER}/.config/${program} ]] && rm /home/${NONROOT_USER}/.config/${program}

    # Symlink the container's config to the persistent config.
    ln -s /.jbdevcontainer/config/${program} /home/${NONROOT_USER}/.config/${program}
    chown --no-dereference ${NONROOT_USER}:${NONROOT_GROUP} /home/${NONROOT_USER}/.config/${program}
  fi

  # Bun uses $XDG_CONFIG_HOME the .bun directory.
  program=bun
  if [[ -d /.jbdevcontainer/config/ ]]
  then
    if [[ ! -e /.jbdevcontainer/config/${program} ]] && [[ -d /home/${NONROOT_USER}/.${program} ]]
    then
      echo "Moving '/home/${NONROOT_USER}/.${program}' to '/.jbdevcontainer/config/'"
      sudoIf mv /home/${NONROOT_USER}/.${program} /.jbdevcontainer/config/${program}
    elif [[ ! -e /.jbdevcontainer/config/${program} ]]
    then
      sudoIf mkdir --parents /.jbdevcontainer/config/${program}
    fi
    sudoIf chown --recursive ${NONROOT_USER}:${NONROOT_GROUP} /.jbdevcontainer/config/${program}

    # The jbdevcontainer image exists but a new container image may not have the symlink in the home directory.
    # Remove the directory so the symlink below works.
    [[ -e /home/${NONROOT_USER}/.${program} ]] && rm -r /home/${NONROOT_USER}/.${program}
    [[ -L /home/${NONROOT_USER}/.${program} ]] && rm /home/${NONROOT_USER}/.${program}

    # Symlink the container's config to the persistent config.
    ln -s /.jbdevcontainer/config/${program} /home/${NONROOT_USER}/.${program}
    chown --no-dereference ${NONROOT_USER}:${NONROOT_GROUP} /home/${NONROOT_USER}/.${program}
  fi

fi

if which bun 2>/dev/null
then

  # Install packages for development
  /usr/local/bin/bun install --global prettier
  /usr/local/bin/bun install --global cspell
  /usr/local/bin/bun install --global corepack
  /usr/local/bin/bun install --global '@anthropic-ai/claude-code'
  /usr/local/bin/bun install --global '@tailwindcss/cli'

  # Update all NPM packages
  /usr/local/bin/bun update --global --latest

fi
