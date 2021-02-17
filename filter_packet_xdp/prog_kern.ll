; ModuleID = 'prog_kern.c'
source_filename = "prog_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.hdr_cursor = type { i8* }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }

@xdp_stats_map = global %struct.bpf_map_def { i32 6, i32 4, i32 16, i32 5, i32 0 }, section "maps", align 4, !dbg !0
@list_mac_addr = global %struct.bpf_map_def { i32 1, i32 6, i32 4, i32 256, i32 0 }, section "maps", align 4, !dbg !22
@_license = global [4 x i8] c"GPL\00", section "license", align 1, !dbg !32
@llvm.used = appending global [5 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.bpf_map_def* @list_mac_addr to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_filter_packet_func to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_pass_func to i8*), i8* bitcast (%struct.bpf_map_def* @xdp_stats_map to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define i32 @xdp_filter_packet_func(%struct.xdp_md* nocapture readonly) #0 section "xdp_filter_packet" !dbg !51 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !64, metadata !DIExpression()), !dbg !89
  %3 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !90
  %4 = load i32, i32* %3, align 4, !dbg !90, !tbaa !91
  %5 = zext i32 %4 to i64, !dbg !96
  %6 = inttoptr i64 %5 to i8*, !dbg !97
  call void @llvm.dbg.value(metadata i8* %6, metadata !65, metadata !DIExpression()), !dbg !98
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !99
  %8 = load i32, i32* %7, align 4, !dbg !99, !tbaa !100
  %9 = zext i32 %8 to i64, !dbg !101
  %10 = inttoptr i64 %9 to i8*, !dbg !102
  call void @llvm.dbg.value(metadata i8* %10, metadata !66, metadata !DIExpression()), !dbg !103
  call void @llvm.dbg.value(metadata i32 1, metadata !88, metadata !DIExpression()), !dbg !104
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !67, metadata !DIExpression()), !dbg !105
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !106, metadata !DIExpression()), !dbg !125
  call void @llvm.dbg.value(metadata i8* %6, metadata !113, metadata !DIExpression()), !dbg !128
  call void @llvm.dbg.value(metadata i8* %10, metadata !115, metadata !DIExpression()), !dbg !129
  call void @llvm.dbg.value(metadata i32 14, metadata !116, metadata !DIExpression()), !dbg !130
  %11 = getelementptr i8, i8* %10, i64 14, !dbg !131
  %12 = icmp ugt i8* %11, %6, !dbg !133
  br i1 %12, label %18, label %13, !dbg !134

; <label>:13:                                     ; preds = %1
  %14 = inttoptr i64 %9 to %struct.ethhdr*, !dbg !135
  call void @llvm.dbg.value(metadata i8* %11, metadata !117, metadata !DIExpression()), !dbg !136
  call void @llvm.dbg.value(metadata i32 0, metadata !124, metadata !DIExpression()), !dbg !137
  call void @llvm.dbg.value(metadata i8* %11, metadata !117, metadata !DIExpression()), !dbg !136
  call void @llvm.dbg.value(metadata i8* %11, metadata !117, metadata !DIExpression()), !dbg !136
  call void @llvm.dbg.value(metadata i32 0, metadata !124, metadata !DIExpression()), !dbg !137
  call void @llvm.dbg.value(metadata %struct.ethhdr* %14, metadata !72, metadata !DIExpression()), !dbg !138
  %15 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %14, i64 0, i32 1, i64 0, !dbg !139
  %16 = tail call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @list_mac_addr to i8*), i8* nonnull %15) #4, !dbg !140
  call void @llvm.dbg.value(metadata i32* %21, metadata !86, metadata !DIExpression()), !dbg !141
  %17 = icmp eq i8* %16, null, !dbg !142
  br i1 %17, label %18, label %20, !dbg !144

; <label>:18:                                     ; preds = %13, %1
  call void @llvm.dbg.value(metadata i32 %22, metadata !88, metadata !DIExpression()), !dbg !104
  %19 = bitcast i32* %2 to i8*, !dbg !145
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %19), !dbg !145
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !150, metadata !DIExpression()) #4, !dbg !145
  call void @llvm.dbg.value(metadata i32 %22, metadata !151, metadata !DIExpression()) #4, !dbg !162
  store i32 1, i32* %2, align 4, !tbaa !163
  br label %25, !dbg !164

; <label>:20:                                     ; preds = %13
  %21 = bitcast i8* %16 to i32*, !dbg !140
  %22 = load i32, i32* %21, align 4, !dbg !165, !tbaa !163
  call void @llvm.dbg.value(metadata i32 %22, metadata !88, metadata !DIExpression()), !dbg !104
  call void @llvm.dbg.value(metadata i32 %22, metadata !88, metadata !DIExpression()), !dbg !104
  %23 = bitcast i32* %2 to i8*, !dbg !145
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %23), !dbg !145
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !150, metadata !DIExpression()) #4, !dbg !145
  call void @llvm.dbg.value(metadata i32 %22, metadata !151, metadata !DIExpression()) #4, !dbg !162
  store i32 %22, i32* %2, align 4, !tbaa !163
  %24 = icmp ugt i32 %22, 4, !dbg !166
  br i1 %24, label %42, label %25, !dbg !164

; <label>:25:                                     ; preds = %18, %20
  %26 = phi i8* [ %19, %18 ], [ %23, %20 ]
  %27 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @xdp_stats_map to i8*), i8* nonnull %26) #4, !dbg !168
  call void @llvm.dbg.value(metadata i8* %27, metadata !152, metadata !DIExpression()) #4, !dbg !169
  %28 = icmp eq i8* %27, null, !dbg !170
  br i1 %28, label %42, label %29, !dbg !172

; <label>:29:                                     ; preds = %25
  %30 = bitcast i8* %27 to i64*, !dbg !173
  %31 = load i64, i64* %30, align 8, !dbg !174, !tbaa !175
  %32 = add i64 %31, 1, !dbg !174
  store i64 %32, i64* %30, align 8, !dbg !174, !tbaa !175
  %33 = load i32, i32* %3, align 4, !dbg !178, !tbaa !91
  %34 = load i32, i32* %7, align 4, !dbg !179, !tbaa !100
  %35 = sub i32 %33, %34, !dbg !180
  %36 = zext i32 %35 to i64, !dbg !181
  %37 = getelementptr inbounds i8, i8* %27, i64 8, !dbg !182
  %38 = bitcast i8* %37 to i64*, !dbg !182
  %39 = load i64, i64* %38, align 8, !dbg !183, !tbaa !184
  %40 = add i64 %39, %36, !dbg !183
  store i64 %40, i64* %38, align 8, !dbg !183, !tbaa !184
  %41 = load i32, i32* %2, align 4, !dbg !185, !tbaa !163
  call void @llvm.dbg.value(metadata i32 %41, metadata !151, metadata !DIExpression()) #4, !dbg !162
  br label %42, !dbg !186

; <label>:42:                                     ; preds = %20, %25, %29
  %43 = phi i8* [ %23, %20 ], [ %26, %29 ], [ %26, %25 ]
  %44 = phi i32 [ 0, %20 ], [ %41, %29 ], [ 0, %25 ]
  call void @llvm.lifetime.end.p0i8(i64 4, i8* %43), !dbg !187
  ret i32 %44, !dbg !188
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: nounwind readnone
define i32 @xdp_pass_func(%struct.xdp_md* nocapture readnone) #2 section "xdp_pass" !dbg !189 {
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !191, metadata !DIExpression()), !dbg !192
  ret i32 2, !dbg !193
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.value(metadata, metadata, metadata) #3

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { nounwind readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind readnone speculatable }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!47, !48, !49}
!llvm.ident = !{!50}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "xdp_stats_map", scope: !2, file: !46, line: 16, type: !24, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !13, globals: !21)
!3 = !DIFile(filename: "prog_kern.c", directory: "/home/joaquin/xdp/case_jah")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 2845, size: 32, elements: !7)
!6 = !DIFile(filename: "../headers/linux/bpf.h", directory: "/home/joaquin/xdp/case_jah")
!7 = !{!8, !9, !10, !11, !12}
!8 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!9 = !DIEnumerator(name: "XDP_DROP", value: 1)
!10 = !DIEnumerator(name: "XDP_PASS", value: 2)
!11 = !DIEnumerator(name: "XDP_TX", value: 3)
!12 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!13 = !{!14, !15, !16, !19}
!14 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!15 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!16 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !17, line: 27, baseType: !18)
!17 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "/home/joaquin/xdp/case_jah")
!18 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!19 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !17, line: 24, baseType: !20)
!20 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!21 = !{!0, !22, !32, !38}
!22 = !DIGlobalVariableExpression(var: !23, expr: !DIExpression())
!23 = distinct !DIGlobalVariable(name: "list_mac_addr", scope: !2, file: !3, line: 23, type: !24, isLocal: false, isDefinition: true)
!24 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map_def", file: !25, line: 33, size: 160, elements: !26)
!25 = !DIFile(filename: "../libbpf/src//build/usr/include/bpf/bpf_helpers.h", directory: "/home/joaquin/xdp/case_jah")
!26 = !{!27, !28, !29, !30, !31}
!27 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !24, file: !25, line: 34, baseType: !18, size: 32)
!28 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !24, file: !25, line: 35, baseType: !18, size: 32, offset: 32)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !24, file: !25, line: 36, baseType: !18, size: 32, offset: 64)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !24, file: !25, line: 37, baseType: !18, size: 32, offset: 96)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !24, file: !25, line: 38, baseType: !18, size: 32, offset: 128)
!32 = !DIGlobalVariableExpression(var: !33, expr: !DIExpression())
!33 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 72, type: !34, isLocal: false, isDefinition: true)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 32, elements: !36)
!35 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!36 = !{!37}
!37 = !DISubrange(count: 4)
!38 = !DIGlobalVariableExpression(var: !39, expr: !DIExpression())
!39 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !40, line: 33, type: !41, isLocal: true, isDefinition: true)
!40 = !DIFile(filename: "../libbpf/src//build/usr/include/bpf/bpf_helper_defs.h", directory: "/home/joaquin/xdp/case_jah")
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = !DISubroutineType(types: !43)
!43 = !{!14, !14, !44}
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!46 = !DIFile(filename: "./../common/xdp_stats_kern.h", directory: "/home/joaquin/xdp/case_jah")
!47 = !{i32 2, !"Dwarf Version", i32 4}
!48 = !{i32 2, !"Debug Info Version", i32 3}
!49 = !{i32 1, !"wchar_size", i32 4}
!50 = !{!"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"}
!51 = distinct !DISubprogram(name: "xdp_filter_packet_func", scope: !3, file: !3, line: 31, type: !52, isLocal: false, isDefinition: true, scopeLine: 32, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !63)
!52 = !DISubroutineType(types: !53)
!53 = !{!54, !55}
!54 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!55 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !56, size: 64)
!56 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 2856, size: 160, elements: !57)
!57 = !{!58, !59, !60, !61, !62}
!58 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !56, file: !6, line: 2857, baseType: !16, size: 32)
!59 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !56, file: !6, line: 2858, baseType: !16, size: 32, offset: 32)
!60 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !56, file: !6, line: 2859, baseType: !16, size: 32, offset: 64)
!61 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !56, file: !6, line: 2861, baseType: !16, size: 32, offset: 96)
!62 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !56, file: !6, line: 2862, baseType: !16, size: 32, offset: 128)
!63 = !{!64, !65, !66, !67, !72, !86, !88}
!64 = !DILocalVariable(name: "ctx", arg: 1, scope: !51, file: !3, line: 31, type: !55)
!65 = !DILocalVariable(name: "data_end", scope: !51, file: !3, line: 33, type: !14)
!66 = !DILocalVariable(name: "data", scope: !51, file: !3, line: 34, type: !14)
!67 = !DILocalVariable(name: "nh", scope: !51, file: !3, line: 35, type: !68)
!68 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "hdr_cursor", file: !69, line: 33, size: 64, elements: !70)
!69 = !DIFile(filename: "./../common/parsing_helpers.h", directory: "/home/joaquin/xdp/case_jah")
!70 = !{!71}
!71 = !DIDerivedType(tag: DW_TAG_member, name: "pos", scope: !68, file: !69, line: 34, baseType: !14, size: 64)
!72 = !DILocalVariable(name: "eth", scope: !51, file: !3, line: 36, type: !73)
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !74, size: 64)
!74 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !75, line: 159, size: 112, elements: !76)
!75 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "/home/joaquin/xdp/case_jah")
!76 = !{!77, !82, !83}
!77 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !74, file: !75, line: 160, baseType: !78, size: 48)
!78 = !DICompositeType(tag: DW_TAG_array_type, baseType: !79, size: 48, elements: !80)
!79 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!80 = !{!81}
!81 = !DISubrange(count: 6)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !74, file: !75, line: 161, baseType: !78, size: 48, offset: 48)
!83 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !74, file: !75, line: 162, baseType: !84, size: 16, offset: 96)
!84 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !85, line: 25, baseType: !19)
!85 = !DIFile(filename: "/usr/include/linux/types.h", directory: "/home/joaquin/xdp/case_jah")
!86 = !DILocalVariable(name: "do_action", scope: !51, file: !3, line: 37, type: !87)
!87 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !54, size: 64)
!88 = !DILocalVariable(name: "action", scope: !51, file: !3, line: 39, type: !16)
!89 = !DILocation(line: 31, column: 43, scope: !51)
!90 = !DILocation(line: 33, column: 38, scope: !51)
!91 = !{!92, !93, i64 4}
!92 = !{!"xdp_md", !93, i64 0, !93, i64 4, !93, i64 8, !93, i64 12, !93, i64 16}
!93 = !{!"int", !94, i64 0}
!94 = !{!"omnipotent char", !95, i64 0}
!95 = !{!"Simple C/C++ TBAA"}
!96 = !DILocation(line: 33, column: 27, scope: !51)
!97 = !DILocation(line: 33, column: 19, scope: !51)
!98 = !DILocation(line: 33, column: 8, scope: !51)
!99 = !DILocation(line: 34, column: 34, scope: !51)
!100 = !{!92, !93, i64 0}
!101 = !DILocation(line: 34, column: 23, scope: !51)
!102 = !DILocation(line: 34, column: 15, scope: !51)
!103 = !DILocation(line: 34, column: 8, scope: !51)
!104 = !DILocation(line: 39, column: 8, scope: !51)
!105 = !DILocation(line: 35, column: 20, scope: !51)
!106 = !DILocalVariable(name: "nh", arg: 1, scope: !107, file: !69, line: 73, type: !110)
!107 = distinct !DISubprogram(name: "parse_ethhdr", scope: !69, file: !69, line: 73, type: !108, isLocal: true, isDefinition: true, scopeLine: 75, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !112)
!108 = !DISubroutineType(types: !109)
!109 = !{!54, !110, !14, !111}
!110 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !68, size: 64)
!111 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!112 = !{!106, !113, !114, !115, !116, !117, !123, !124}
!113 = !DILocalVariable(name: "data_end", arg: 2, scope: !107, file: !69, line: 73, type: !14)
!114 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !107, file: !69, line: 74, type: !111)
!115 = !DILocalVariable(name: "eth", scope: !107, file: !69, line: 76, type: !73)
!116 = !DILocalVariable(name: "hdrsize", scope: !107, file: !69, line: 77, type: !54)
!117 = !DILocalVariable(name: "vlh", scope: !107, file: !69, line: 78, type: !118)
!118 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !119, size: 64)
!119 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "vlan_hdr", file: !69, line: 42, size: 32, elements: !120)
!120 = !{!121, !122}
!121 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !119, file: !69, line: 43, baseType: !84, size: 16)
!122 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_encapsulated_proto", scope: !119, file: !69, line: 44, baseType: !84, size: 16, offset: 16)
!123 = !DILocalVariable(name: "h_proto", scope: !107, file: !69, line: 79, type: !19)
!124 = !DILocalVariable(name: "i", scope: !107, file: !69, line: 80, type: !54)
!125 = !DILocation(line: 73, column: 60, scope: !107, inlinedAt: !126)
!126 = distinct !DILocation(line: 46, column: 6, scope: !127)
!127 = distinct !DILexicalBlock(scope: !51, file: !3, line: 46, column: 6)
!128 = !DILocation(line: 73, column: 70, scope: !107, inlinedAt: !126)
!129 = !DILocation(line: 76, column: 17, scope: !107, inlinedAt: !126)
!130 = !DILocation(line: 77, column: 6, scope: !107, inlinedAt: !126)
!131 = !DILocation(line: 85, column: 14, scope: !132, inlinedAt: !126)
!132 = distinct !DILexicalBlock(scope: !107, file: !69, line: 85, column: 6)
!133 = !DILocation(line: 85, column: 24, scope: !132, inlinedAt: !126)
!134 = !DILocation(line: 85, column: 6, scope: !107, inlinedAt: !126)
!135 = !DILocation(line: 89, column: 10, scope: !107, inlinedAt: !126)
!136 = !DILocation(line: 78, column: 19, scope: !107, inlinedAt: !126)
!137 = !DILocation(line: 80, column: 6, scope: !107, inlinedAt: !126)
!138 = !DILocation(line: 36, column: 17, scope: !51)
!139 = !DILocation(line: 52, column: 50, scope: !51)
!140 = !DILocation(line: 52, column: 14, scope: !51)
!141 = !DILocation(line: 37, column: 7, scope: !51)
!142 = !DILocation(line: 53, column: 7, scope: !143)
!143 = distinct !DILexicalBlock(scope: !51, file: !3, line: 53, column: 6)
!144 = !DILocation(line: 53, column: 6, scope: !51)
!145 = !DILocation(line: 24, column: 46, scope: !146, inlinedAt: !161)
!146 = distinct !DISubprogram(name: "xdp_stats_record_action", scope: !46, file: !46, line: 24, type: !147, isLocal: true, isDefinition: true, scopeLine: 25, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !149)
!147 = !DISubroutineType(types: !148)
!148 = !{!16, !55, !16}
!149 = !{!150, !151, !152}
!150 = !DILocalVariable(name: "ctx", arg: 1, scope: !146, file: !46, line: 24, type: !55)
!151 = !DILocalVariable(name: "action", arg: 2, scope: !146, file: !46, line: 24, type: !16)
!152 = !DILocalVariable(name: "rec", scope: !146, file: !46, line: 30, type: !153)
!153 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !154, size: 64)
!154 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "datarec", file: !155, line: 10, size: 128, elements: !156)
!155 = !DIFile(filename: "./../common/xdp_stats_kern_user.h", directory: "/home/joaquin/xdp/case_jah")
!156 = !{!157, !160}
!157 = !DIDerivedType(tag: DW_TAG_member, name: "rx_packets", scope: !154, file: !155, line: 11, baseType: !158, size: 64)
!158 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !17, line: 31, baseType: !159)
!159 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!160 = !DIDerivedType(tag: DW_TAG_member, name: "rx_bytes", scope: !154, file: !155, line: 12, baseType: !158, size: 64, offset: 64)
!161 = distinct !DILocation(line: 63, column: 9, scope: !51)
!162 = !DILocation(line: 24, column: 57, scope: !146, inlinedAt: !161)
!163 = !{!93, !93, i64 0}
!164 = !DILocation(line: 26, column: 6, scope: !146, inlinedAt: !161)
!165 = !DILocation(line: 56, column: 20, scope: !143)
!166 = !DILocation(line: 26, column: 13, scope: !167, inlinedAt: !161)
!167 = distinct !DILexicalBlock(scope: !146, file: !46, line: 26, column: 6)
!168 = !DILocation(line: 30, column: 24, scope: !146, inlinedAt: !161)
!169 = !DILocation(line: 30, column: 18, scope: !146, inlinedAt: !161)
!170 = !DILocation(line: 31, column: 7, scope: !171, inlinedAt: !161)
!171 = distinct !DILexicalBlock(scope: !146, file: !46, line: 31, column: 6)
!172 = !DILocation(line: 31, column: 6, scope: !146, inlinedAt: !161)
!173 = !DILocation(line: 38, column: 7, scope: !146, inlinedAt: !161)
!174 = !DILocation(line: 38, column: 17, scope: !146, inlinedAt: !161)
!175 = !{!176, !177, i64 0}
!176 = !{!"datarec", !177, i64 0, !177, i64 8}
!177 = !{!"long long", !94, i64 0}
!178 = !DILocation(line: 39, column: 25, scope: !146, inlinedAt: !161)
!179 = !DILocation(line: 39, column: 41, scope: !146, inlinedAt: !161)
!180 = !DILocation(line: 39, column: 34, scope: !146, inlinedAt: !161)
!181 = !DILocation(line: 39, column: 19, scope: !146, inlinedAt: !161)
!182 = !DILocation(line: 39, column: 7, scope: !146, inlinedAt: !161)
!183 = !DILocation(line: 39, column: 16, scope: !146, inlinedAt: !161)
!184 = !{!176, !177, i64 8}
!185 = !DILocation(line: 41, column: 9, scope: !146, inlinedAt: !161)
!186 = !DILocation(line: 41, column: 2, scope: !146, inlinedAt: !161)
!187 = !DILocation(line: 42, column: 1, scope: !146, inlinedAt: !161)
!188 = !DILocation(line: 63, column: 2, scope: !51)
!189 = distinct !DISubprogram(name: "xdp_pass_func", scope: !3, file: !3, line: 67, type: !52, isLocal: false, isDefinition: true, scopeLine: 68, flags: DIFlagPrototyped, isOptimized: true, unit: !2, variables: !190)
!190 = !{!191}
!191 = !DILocalVariable(name: "ctx", arg: 1, scope: !189, file: !3, line: 67, type: !55)
!192 = !DILocation(line: 67, column: 34, scope: !189)
!193 = !DILocation(line: 69, column: 2, scope: !189)
