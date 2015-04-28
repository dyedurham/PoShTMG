Powershell TMG Configuration Module
=========

## Description

PoShTMG allows you to configure a functional TMG array from a Powershell console on a TMG array member.

## To Install

1. Create a PoShTMG directory in your Powershell Modules directory - usually 'C:\Program Files\WindowsPowerShell\Modules'.
(hint: New-Item -Type directory -Path 'C:\Program Files\WindowsPowerShell\Modules\PoShTMG' )
2. Install the PoShTMG.psm1 file from here to the directory.

## Usage

Command help is available by Get-Help (command).

The workflow of the module is create or set, then apply separately. This is due to the usually long time TMG takes to apply new settings to the array - so make all of your changes then run Save-TMGxxx once per rule type.

## Contributing
We'd love everyone and anyone to contribute!

1. Check the issue list for outstanding tasks or create new ones.
2. Send a pull request with completed code and unit/integration tests.
3. Need help? or support getting your change through? Start a discussion in the issue and if needs be, we can take it offline from there.