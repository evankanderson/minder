-- Copyright 2024 Stacklok, Inc
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

BEGIN;

-- The following two indexes on alert_events and remediation_events
-- are necessary to optimize deletions.
CREATE INDEX alert_events_evaluation_id_fk_idx ON alert_events (evaluation_id);
CREATE INDEX remediation_events_evaluation_id_fk_idx ON remediation_events (evaluation_id);

COMMIT;
