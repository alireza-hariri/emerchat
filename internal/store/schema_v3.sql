-- Group photos: version token of FilesDir/groups/<chatId>, '' = none.
ALTER TABLE chats ADD COLUMN photo TEXT NOT NULL DEFAULT '';
