ALTER TABLE applications ADD COLUMN theme_data JSONB;
ALTER TABLE applications ADD COLUMN footer_html TEXT;
ALTER TABLE applications ADD COLUMN form_background_url_mobile VARCHAR(512);
-- Resource UUID, rather than a mutable application name, is the theme binding.
CREATE UNIQUE INDEX one_marketplace_theme_per_application ON casdoor_objects((document->>'resourceId'))
WHERE kind='integration' AND document->>'type'='theme';
