on run argv
    set shellCommand to "exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=en_US.UTF-8 /bin/bash"
    repeat with itemValue in argv
        set shellCommand to shellCommand & " " & quoted form of (contents of itemValue)
    end repeat
    try
        do shell script shellCommand with administrator privileges
        return "completed"
    on error messageText number errorNumber
        if errorNumber is -128 then return "cancelled"
        error messageText number errorNumber
    end try
end run
