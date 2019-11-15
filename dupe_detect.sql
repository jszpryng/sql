--Duplicate Detection QA code

-- Step 1a: create table of duplicate_ids
CREATE TEMP TABLE duplicate_ids AS
SELECT uniqueID as uid
FROM my.Table
GROUP BY uniqueID
HAVING COUNT(*) > 1;

-- Step 1b: Extract one copy of all the duplicate rows
CREATE TEMP TABLE my.NewTable(LIKE my.Table);

INSERT INTO my.NewTable
SELECT DISTINCT *
FROM my.Table
WHERE uniqueID IN
(
 SELECT uid
 FROM duplicate_ids
);

-- Step 1c: Remove all rows that were duplicated (all copies).
DELETE FROM my.Table
WHERE uniqueID IN
(
  SELECT uid
  FROM duplicate_ids
);

-- Step 1d: Insert back in the single copies
INSERT INTO my.Table
SELECT *
FROM my.NewTable;

-- Step 1e: Cleanup
DROP TABLE duplicate_ids;
DROP TABLE my.NewTable;
