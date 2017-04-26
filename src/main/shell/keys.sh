#!/bin/sh

# This file is part of nMix.
# Copyright (C) 2015-2016-2017  Agora Voting SL <agora@agoravoting.com>

# nMix is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# nMix  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with nMix.  If not, see <http://www.gnu.org/licenses/>.


# generate public and private key in ssh format
ssh-keygen -t rsa -b 4096 -f keys/id_rsa -q -N ""

# generate public key from ssh keygen private key
openssl rsa -in keys/id_rsa -pubout > keys/id_rsa.pub.pem

# generate private key in pkcs8 pem format from ssh-keygen private key
openssl pkcs8 -topk8 -inform PEM -outform PEM -in keys/id_rsa -out keys/id_rsa.pem -nocrypt