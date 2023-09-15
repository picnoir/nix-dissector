local nix_proto = Proto("nix", "Nix Daemon Protocol")

local dst_field = ProtoField.uint64("nix.dst", "Destination FD")
local src_field = ProtoField.uint64("nix.src", "Source FD")

local client_hello_field = ProtoField.bytes("nix.clienthello", "Client Hello")
local client_hello_magic_field = ProtoField.uint64("nix.clienthello.magic", "Client magic number")
local client_hello_version_field = ProtoField.uint64("nix.clienthello.version", "Client version")

local daemon_hello_field = ProtoField.bytes("nix.daemonhello", "Daemon Hello")
local daemon_hello_magic_field = ProtoField.uint64("nix.daemonhello.magic", "Daemon magic number")
local daemon_hello_version_field = ProtoField.uint64("nix.daemonhello.protolversion", "Protocol Version")

local op_name_field = ProtoField.string("nix.opname", "Operation Name")

local op_addtostore = ProtoField.bytes("nix.addtostore", "Add to store operation")
local op_addtostore_name = ProtoField.string("nix.addtostore.name", "Add to store name")
local op_addtostore_camstr = ProtoField.string("nix.addtostore.camstr", "Add to store camstr")
local op_addtostore_nb_references = ProtoField.uint64("nix.addtostore.nbreferences", "Number of References")
local op_addtostore_reference = ProtoField.string("nix.addtostore.reference", "Reference")
local op_addtostore_repairflag = ProtoField.bool("nix.addtostore.repairflag", "Repair Flag")
local op_addtostore_payload = ProtoField.bytes("nix.addtostore.payload", "Request Payload")
local op_addtostore_response = ProtoField.bytes("nix.addtostore.response", "Response")

local op_setoptions = ProtoField.bytes("nix.setoptions", "Set connection options")
local op_setoptions_keepfailed = ProtoField.bool("nix.setoptions.keepfailed", "Keep the failed build directory")
local op_setoptions_keepgoing = ProtoField.bool("nix.setoptions.keepgoing", "Keep on going after a failed build")
local op_setoptions_tryfallback = ProtoField.bool("nix.setoptions.tryfallback", "Fallback")
local op_setoptions_verbosity = ProtoField.uint64("nix.setoptions.verbosity", "Verbosity")
local op_setoptions_maxbuildjobs = ProtoField.uint64("nix.setoptions.maxbuildjobs", "Max build jobs")
local op_setoptions_maxsilenttime = ProtoField.uint64("nix.setoptions.maxsilenttime", "Max Silent Time")
local op_setoptions_verbosebuild = ProtoField.uint64("nix.setoptions.verbosebuild", "Verbosity level")
local op_setoptions_buildcores = ProtoField.uint64("nix.setoptions.buildcores", "NB Build cores")
local op_setoptions_usesubstitutes = ProtoField.bool("nix.setoptions.usesubstitutes", "Use substitutes")
local op_setoptions_nbclientoverrides = ProtoField.uint64("nix.setoptions.nbclientoverrides", "Nb Client Overrides")
local op_setoptions_clientoverridename = ProtoField.uint64("nix.setoptions.clientoverridename", "Client Override key")
local op_setoptions_clientoverridevalue = ProtoField.uint64("nix.setoptions.clientoverridevalue", "Client Override Value")

op_addtostore_step = 0

nix_proto.fields = {
   dst_field,
   src_field,
   op_field,
   first_byte_field,
   client_hello_field,
   client_hello_magic_field,
   client_hello_version_field,
   daemon_hello_field,
   daemon_hello_magic_field,
   daemon_hello_version_field,
   op_name_field,
   op_addtostore,
   op_addtostore_name,
   op_addtostore_camstr,
   op_addtostore_nb_references,
   op_addtostore_reference,
   op_addtostore_repairflag,
   op_addtostore_payload,
   op_addtostore_response,

   op_setoptions,
   op_setoptions_keepfailed,
   op_setoptions_keepgoing,
   op_setoptions_tryfallback,
   op_setoptions_verbosity,
   op_setoptions_maxbuildjobs,
   op_setoptions_maxsilenttime,
   op_setoptions_verbosebuild,
   op_setoptions_buildcores,
   op_setoptions_usesubstitutes,
   op_setoptions_nbclientoverrides,
   op_setoptions_clientoverridename,
   op_setoptions_clientoverridevalue,
}

local op_table = {
   [1] = "IsValidPath",
   [3] = "HasSubstitutes",
   [4] = "QuaryPathHash",
   [5] = "QueryReferences",
   [6] = "QueryReferrers",
   [7] = "AddToStore",
   [8] = "AddTextToStore",
   [9] = "BuildPaths",
   [10] = "EnsurePath",
   [11] = "AddTempRoot",
   [12] = "AddIndirectRoot",
   [13] = "SyncWithGC",
   [14] = "FindRoots",
   [16] = "ExportPath",
   [18] = "QueryDeriver",
   [19] = "SetOptions",
   [20] = "CollectGarbage",
   [21] = "QuerySubstitutablePathInfo",
   [22] = "QueryDerivationOutputs",
   [23] = "QueryAllValidPaths",
   [24] = "QueryFailedPaths",
   [25] = "ClearFailedPaths",
   [26] = "QueryPathInfo",
   [27] = "ImportPaths",
   [28] = "QueryDerivationOutputNames",
   [29] = "QueryPathFromHashPart",
   [30] = "QuerySubstitutablePathInfos",
   [31] = "QueryValidPaths",
   [32] = "QuerySubstitutablePaths",
   [33] = "QueryValidDerivers",
   [34] = "OptimiseStore",
   [35] = "VerifyStore",
   [36] = "BuildDerivation",
   [37] = "AddSignatures",
   [38] = "NarFromPath",
   [39] = "AddToStoreNar",
   [40] = "QueryMissing",
   [41] = "QueryDerivationOutputMap",
   [42] = "RegisterDrvOutput",
   [43] = "QueryRealisation",
   [44] = "AddMultipleToStore",
   [45] = "AddBuildLog",
   [46] = "BuildPathsWithResults",
}

function parse_client_hello(tvb, pinfo, tree, offset)
   local subtree = tree:add(client_hello_field, tvb:range(offset, 8))

   subtree:add_le(client_hello_magic_field, tvb(offset,8))
   return offset + 8
end

function parse_daemon_hello(tvb, pinfo, tree, offset)
   local subtree = tree:add(daemon_hello_field, tvb:range(offset, 16))

   subtree:add_le(daemon_hello_magic_field, tvb(offset,8))
   offset = offset + 8

   subtree:add_le(daemon_hello_version_field, tvb(offset,8))
   return offset + 8
end

-- Reads a Nix daemon string from tvb.
-- The Nix daemon strings are composed of two fields:
-- 1. The size of the string (8 bytes)
-- 2. The string itself, 8-aligned (padding with \0), non null
--    terminated.
function read_string(tvb, pinfo, tree, offset)
   local str

   -- Read size (u_size)
   local size = tvb(offset,4):le_int()
   local offset = offset + 8


   -- Strings are 8-aligned. We need to discard the potential padding.
   if (size % 8) ~= 0 then
      -- Parting the string. They are null-padded, so we'll get a the
      -- null terminaison wireshark is expecting for free.
      str = tvb(offset,size):string()
      offset = offset + (size + (8 - (size % 8)))
   else
      -- The string is already 8-aligned. This is a bit annoying:
      -- Wireshark expects the strings to be null terminated. Nix
      -- daemon is not null-terminating the strings it sends to the
      -- wire.
      --
      -- We have to extract the string to a new tvb to append a null
      -- byte at the end. We can then send this new null-terminated
      -- string to wireshark.
      --
      -- Note: the offset indexes the original tvb, not the
      -- temporarily created one. There's no need to take this new
      -- null bit into account.
      local tvb_clone = tvb:bytes(offset, size + 1)
      tvb_clone:set_index(size, 0)
      str = tvb_clone(0,size+1):tvb():range(0,size+1):string()
      offset = offset + size
   end

   return offset, str
end

function parse_add_to_store(tvb, pinfo, tree, offset)
   local initoffset = offset

   offsetname, name  = read_string(tvb, pinfo, tree, offset)
   offset, camstr  = read_string(tvb, pinfo, tree, offsetname)

   local subtree = tree:add(op_addtostore, tvb(initoffset, offset - initoffset))
   subtree:add(op_addtostore_name, tvb(initoffset, offsetname - initoffset), name)
   subtree:add(op_addtostore_camstr, tvb(offsetname, offset - offsetname), camstr)

   local nb_references = tvb(offset,4):le_int()
   subtree:add_le(op_addtostore_nb_references, tvb(offset,8))
   offset = offset + 8
   for i=1, nb_references do
      local reference
      local prevoffset = offset
      offset, reference = read_string(tvb, pinfo, tree, offset)
      subtree:add(op_addtostore_reference, tvb(prevoffset, offset - prevoffset), reference)
   end

   local repairflag = subtree:add(op_addtostore_repairflag, tvb(offset, 1))

   offset = offset + 8
   op_addtostore_step = 2

   return offset
end

function process_op_addtostore_step(tvb, pinfo, tree, offset)
   if op_addtostore_step == 2 then
      local subtree = tree:add(op_addtostore, tvb(offset, tvb:len() - offset))
      subtree:add(op_addtostore_payload, tvb(offset, tvb:len() - offset))
   elseif op_addtostore_step == 1 then
      local subtree = tree:add(op_addtostore, tvb(offset, tvb:len() - offset))
      subtree:add(op_addtostore_response, tvb(offset, tvb:len() - offset))
   end

   op_addtostore_step = op_addtostore_step - 1
end

function parse_set_options(tvb, pinfo, tree, offset)
   local subtree = tree:add(op_setoptions, tvb(offset, tvb:len() - offset))

   subtree:add(op_setoptions_keepfailed, tvb(offset, 1))
   offset = offset + 8

   subtree:add(op_setoptions_keepgoing, tvb(offset, 1))
   offset = offset + 8

   subtree:add(op_setoptions_tryfallback, tvb(offset, 1))
   offset = offset + 8

   subtree:add_le(op_setoptions_verbosity, tvb(offset, 8))
   offset = offset + 8

   subtree:add_le(op_setoptions_maxbuildjobs, tvb(offset, 8))
   offset = offset + 8

   subtree:add_le(op_setoptions_maxsilenttime, tvb(offset, 8))
   offset = offset + 8

   -- Obsolete useBuildHook
   offset = offset + 8

   subtree:add_le(op_setoptions_verbosebuild, tvb(offset, 8))
   offset = offset + 8

   -- Obsolete logtype
   offset = offset + 8

   -- Obsolete printBuildTrace
   offset = offset + 8

   subtree:add_le(op_setoptions_buildcores, tvb(offset, 8))
   offset = offset + 8

   subtree:add(op_setoptions_usesubstitutes, tvb(offset, 1))
   offset = offset + 8

   local nb_client_overrides = tvb(offset, 4):le_int()
   subtree:add_le(op_setoptions_nbclientoverrides, tvb(offset, 8))
   offset = offset + 8

   for i=1, nb_client_overrides do
      local initoffset = offset
      local nameoffset
      local name
      local value
      nameoffset, name = read_string(tvb, pinfo, tree, offset)
      offset, value = read_string(tvb, pinfo, tree, offset)
      subtree:add(op_setoptions_clientoverridename, tvb(initoffset, nameoffset - initoffset), name)
      subtree:add(op_setoptions_clientoverridevalue, tvb(initoffset, offset - nameoffset), value)
   end

   return offset
end

function parse_op(tvb, pinfo, tree, offset, op)
   tree:add(op_name_field, tvb(offset, 8), op_table[op])
   offset = offset + 8

   if op_table[op] == "AddToStore" then
      offset = parse_add_to_store(tvb, pinfo, tree, offset)
   elseif op_table[op] == "SetOptions" then
      offset = parse_set_options(tvb, pinfo, tree, offset)
   end
   return offset
end


function nix_proto.dissector(tvb, pinfo, tree)
   local offset = 0
   local subtree = tree:add(nix_proto, tvb(), "Nix Daemon Protocol Data")
   local dst = subtree:add(dst_field, tvb(offset, 8))
   offset = offset + 8

   local src = subtree:add(src_field, tvb(offset, 8))
   offset = offset + 8

   local first_word = tvb(offset, 4):le_uint()

   if op_addtostore_step > 0 then
      process_op_addtostore_step(tvb, pinfo, subtree, offset)
   elseif first_word == 0x6e697863 then
      offset = parse_client_hello(tvb, pinfo, subtree, offset)
   elseif first_word == 0x6478696f then
      offset = parse_daemon_hello(tvb, pinfo, subtree, offset)
   elseif op_table[first_word] ~= nil then
      offset = parse_op(tvb, pinfo, subtree, offset, first_word)
   end

   pinfo.cols.protocol = "Nix Daemon"
   pinfo.cols.dst = tostring(tvb(0, 8):uint64())
   pinfo.cols.src = tostring(tvb(8, 8):uint64())
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER0, nix_proto)
