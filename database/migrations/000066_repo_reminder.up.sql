-- SPDX-FileCopyrightText: Copyright 2024 The Minder Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE repositories ADD COLUMN reminder_last_sent TIMESTAMP;
