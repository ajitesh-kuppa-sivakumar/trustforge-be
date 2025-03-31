/*
  # Create scans table and related security policies

  1. New Tables
    - `scans`
      - `scan_id` (uuid, primary key)
      - `user_id` (uuid, references auth.users)
      - `file_name` (text)
      - `file_url` (text)
      - `scan_status` (text)
      - `report_data` (jsonb)
      - `tf_score` (numeric)
      - `pdf_report_url` (text)
      - `created_at` (timestamptz)
      - `updated_at` (timestamptz)

  2. Security
    - Enable RLS on `scans` table
    - Add policies for:
      - Users can read their own scans
      - Users can create their own scans
      - Users can update their own scans
*/

CREATE TABLE IF NOT EXISTS scans (
  scan_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  file_name text NOT NULL,
  file_url text,
  scan_status text NOT NULL DEFAULT 'pending',
  report_data jsonb,
  tf_score numeric CHECK (tf_score >= 0 AND tf_score <= 100),
  pdf_report_url text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own scans"
  ON scans
  FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create own scans"
  ON scans
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own scans"
  ON scans
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Create an index for faster lookups by user_id
CREATE INDEX IF NOT EXISTS scans_user_id_idx ON scans(user_id);

-- Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Create a trigger to automatically update the updated_at timestamp
CREATE TRIGGER update_scans_updated_at
  BEFORE UPDATE ON scans
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();