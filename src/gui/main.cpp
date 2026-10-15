#include <Windows.h>
#include <d3d11.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <wrl/client.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"


import std;
import secure_erase.application;
import secure_erase.metadata;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace
{
    namespace frontend = secure_erase::frontend;
    namespace engine = secure_erase::engine;
    using Microsoft::WRL::ComPtr;

    class window_icon
    {
    public:
        window_icon(HINSTANCE instance, int width, int height) noexcept
            : value_(static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON,
                width, height, LR_DEFAULTCOLOR)))
        {
        }

        ~window_icon()
        {
            if (value_ != nullptr)
            {
                DestroyIcon(value_);
            }
        }

        window_icon(const window_icon&) = delete;
        window_icon& operator=(const window_icon&) = delete;

        [[nodiscard]] HICON get() const noexcept
        {
            return value_;
        }

    private:
        HICON value_{};
    };

    // BEGIN_GUI_QUEUE_CONTRACT: Pure presentation bookkeeping; no filesystem access.
    struct queue_run
    {
        std::shared_ptr<const engine::frozen_plan> plan;
        std::vector<std::string> roots;
        std::uint64_t generation{};
        std::shared_ptr<const engine::run_report> preceding_report;
        bool quick_mode{};
        bool awaiting_report{};
        bool paged_quick{};
    };

    std::string queue_namespace_key(std::string_view path)
    {
        std::string key(path);
        std::replace(key.begin(), key.end(), '/', '\\');
        if (key.starts_with("\\\\?\\"))
        {
            key.erase(0, 4);
        }
        while (key.size() > 3 && key.back() == '\\')
        {
            key.pop_back();
        }
        // SECURITY: Case, dot components and short aliases are not guessed. An
        // unmatched input stays queued, including a deduplicated hard-link alias.
        return key;
    }

    std::optional<queue_run> bind_queue_run(const std::optional<queue_run>& previous,
        std::shared_ptr<const engine::frozen_plan> plan,
        std::shared_ptr<const engine::run_report> preceding_report, bool resumed,
        const std::vector<std::string>& queue, std::uint64_t generation,
        std::uint64_t preview_generation, bool quick_mode = false, bool paged_quick = false)
    {
        if (!plan || queue.empty() || (paged_quick && !quick_mode))
        {
            return std::nullopt;
        }
        if (resumed)
        {
            if (!previous || previous->quick_mode != quick_mode || previous->paged_quick != paged_quick ||
                previous->plan->job_id != plan->job_id ||
                previous->plan->fingerprint != plan->fingerprint ||
                previous->generation != generation || previous->roots != queue)
            {
                return std::nullopt;
            }
        }
        else if (preview_generation != generation)
        {
            return std::nullopt;
        }
        return queue_run{std::move(plan), queue, generation, std::move(preceding_report), quick_mode, true, paged_quick};
    }

    bool reconcile_queue_report(std::optional<queue_run>& binding,
        std::vector<std::string>& queue, std::uint64_t& generation,
        const std::shared_ptr<const engine::run_report>& report, bool busy, bool executing)
    {
        if (!binding || binding->paged_quick || !binding->awaiting_report || busy || executing)
        {
            return false;
        }
        // CONTRACT: Consume each accepted execution once, including failures and
        // mismatches. Re-adding a path cannot be affected by an older report.
        auto& run = *binding;
        run.awaiting_report = false;
        const bool fresh_report = report && report != run.preceding_report;
        run.preceding_report.reset();
        if (!fresh_report || report->job_id != run.plan->job_id ||
            ((run.quick_mode || !report->plan_fingerprint.empty()) && report->plan_fingerprint != run.plan->fingerprint) ||
            run.generation != generation || run.roots != queue)
        {
            binding.reset();
            return false;
        }
        if (report->status != "completed" && report->status != "partial_failure" &&
            report->status != "paused" && report->status != "cancelled_partial" &&
            report->status != "audit_finalization_failed" && report->status != "checkpoint_cleanup_failed")
        {
            return false;
        }
        // CONTRACT: These views borrow immutable report/namespace storage only
        // for this reconciliation; no per-frame target-string copies are made.
        std::unordered_map<std::string_view, bool> outcomes;
        outcomes.reserve(report->targets.size());
        for (const auto& outcome : report->targets)
        {
            const bool completed = outcome.deleted &&
                (outcome.code == "deleted_logical_overwrite_verified_residual_risk" ||
                    outcome.code == "deleted_only_residual_risk" ||
                    outcome.code == "completed_from_authenticated_checkpoint" ||
                    outcome.code == "deleted_quick_namespace_removed");
            const auto [found, inserted] = outcomes.emplace(outcome.identity, completed);
            if (!inserted)
            {
                found->second = false;
            }
        }
        std::unordered_map<std::string, bool> namespaces;
        namespaces.reserve(run.plan->targets.size());
        std::vector<std::string_view> incomplete_paths;
        for (const auto& target : run.plan->targets)
        {
            const auto outcome = outcomes.find(target.identity);
            const bool completed = outcome != outcomes.end() && outcome->second;
            auto key = queue_namespace_key(target.path);
            const auto [found, inserted] = namespaces.emplace(std::move(key), completed);
            if (!inserted)
            {
                found->second = false;
            }
            if (!completed || !inserted)
            {
                incomplete_paths.push_back(found->first);
            }
        }
        std::sort(incomplete_paths.begin(), incomplete_paths.end());
        const auto removed = std::erase_if(queue, [&](const std::string& root)
        {
            auto key = queue_namespace_key(root);
            const auto target = namespaces.find(key);
            if (target == namespaces.end() || !target->second)
            {
                return false;
            }
            // CONTRACT: A selected directory is retained when any frozen child
            // is incomplete, even if another actor has already removed its name.
            key.push_back('\\');
            const auto child = std::lower_bound(incomplete_paths.begin(), incomplete_paths.end(), key);
            return child == incomplete_paths.end() || !child->starts_with(key);
        });
        if (removed == 0)
        {
            return false;
        }
        ++generation;
        run.generation = generation;
        run.roots = queue;
        if (queue.empty())
        {
            binding.reset();
        }
        return true;
    }
    bool reconcile_paged_queue_report(std::optional<queue_run>& binding,
        std::vector<std::string>& queue, std::uint64_t& generation,
        const std::shared_ptr<const engine::run_report>& report, bool busy, bool executing,
        bool proof_ready, std::string_view proof_job, std::string_view proof_fingerprint,
        std::span<const std::string> completed_inputs)
    {
        if (!binding || !binding->paged_quick || !binding->awaiting_report || busy || executing)
        {
            return false;
        }
        auto& run = *binding;
        // SECURITY: Metadata-only reports contain no target outcomes. Only the
        // worker's explicit original-input proof authorizes presentation removal.
        if (!report || report == run.preceding_report || !proof_ready)
        {
            return false;
        }
        run.awaiting_report = false;
        run.preceding_report.reset();
        if (report->job_id != run.plan->job_id || report->plan_fingerprint != run.plan->fingerprint ||
            proof_job != report->job_id || proof_fingerprint != report->plan_fingerprint ||
            run.generation != generation || run.roots != queue)
        {
            binding.reset();
            return false;
        }
        if (report->status != "completed" && report->status != "partial_failure" &&
            report->status != "paused" && report->status != "cancelled_partial" &&
            report->status != "audit_finalization_failed")
        {
            return false;
        }
        std::unordered_set<std::string_view> completed;
        completed.reserve(completed_inputs.size());
        for (const auto& path : completed_inputs)
        {
            completed.insert(path);
        }
        const auto removed = std::erase_if(queue, [&](const std::string& path)
        {
            return completed.contains(path);
        });
        if (removed == 0)
        {
            return false;
        }
        ++generation;
        run.generation = generation;
        run.roots = queue;
        if (queue.empty())
        {
            binding.reset();
        }
        return true;
    }

    struct confirmation_binding
    {
        std::string job_id;
        std::string fingerprint;
        std::uint64_t generation{};
        bool quick_mode{};
    };

    struct page_request_binding
    {
        std::string job_id;
        std::string fingerprint;
        std::uint64_t cursor{};
        bool failures_only{};
    };

    bool confirmation_matches(const std::optional<confirmation_binding>& confirmation,
        const std::shared_ptr<const engine::frozen_plan>& plan, std::uint64_t generation, bool quick_mode)
    {
        return confirmation && plan && confirmation->job_id == plan->job_id &&
            confirmation->fingerprint == plan->fingerprint && confirmation->generation == generation &&
            confirmation->quick_mode == quick_mode;
    }

    bool manual_recovery_allowed(const engine::run_report& report, bool quick_mode)
    {
        return !quick_mode || std::ranges::none_of(report.targets, [](const auto& outcome)
        {
            return outcome.code == "quick_not_attempted";
        });
    }

    bool paged_manual_recovery_allowed(std::size_t total, std::size_t attempted, std::size_t pending)
    {
        // SECURITY: Compact reports intentionally have no per-target vector.
        // Explicit complete first-pass counts are required; zero is not success.
        return total != 0 && attempted == total && pending == 0;
    }

    // END_GUI_QUEUE_CONTRACT

    struct application_state
    {
        frontend::application app;
        HWND window{};
        ComPtr<ID3D11Device> device;
        ComPtr<ID3D11DeviceContext> context;
        ComPtr<IDXGISwapChain> swap_chain;
        ComPtr<ID3D11RenderTargetView> render_target;
        UINT pending_width{};
        UINT pending_height{};
        bool minimized{};
        bool exit_requested{};
        bool graphics_failed{};
        bool imgui_ready{};
        bool irreversible{};
        bool quick_mode{true};
        bool retry_requested{};
        bool preparation_requested{};
        bool preparation_just_started{};
        bool confirmation_visible{};
        bool details_open{};
        bool failure_popup_open{};
        bool last_run_quick{};
        std::shared_ptr<const engine::frozen_plan> last_run_plan;
        std::string force_job;
        std::optional<std::size_t> selected_input;
        std::size_t input_page{};
        std::size_t target_page{};
        std::size_t failure_page{};
        std::size_t report_page{};
        std::uint64_t quick_preview_cursor{};
        std::uint64_t quick_failure_cursor{};
        std::vector<std::uint64_t> quick_preview_history;
        std::vector<std::uint64_t> quick_failure_history;
        std::optional<page_request_binding> page_request;
        int memory_budget_mib{64};
        int max_device_workers{4};
        int ssd_queue_depth{2};
        int io_budget_mib{};
        std::vector<std::string> queue;
        std::unordered_set<std::string> input_index;
        std::uint64_t input_index_generation{};
        std::uint64_t queue_generation{};
        std::uint64_t preview_generation{};
        std::uint64_t input_admission_remaining{};
        std::chrono::steady_clock::time_point input_admission_sampled{};
        std::optional<queue_run> queue_execution;
        std::string preview_fingerprint;
        std::unordered_set<std::string> downgrade_tokens;
        std::size_t selected_target{};
        std::array<char, 32768> typed_path{};
        std::string ui_error;
        std::optional<engine::locking_process> force_process;
        std::string force_path;
        std::optional<confirmation_binding> confirmation;
        std::optional<confirmation_binding> force_confirmation;
        std::shared_ptr<const engine::run_report> failure_report;
        std::unordered_map<std::string, const engine::target_snapshot*> failed_targets;
        std::vector<std::pair<const engine::target_snapshot*, const engine::target_outcome*>> failed_outcomes;
        std::string selected_failure_path;
        std::chrono::steady_clock::time_point run_started{};
        std::size_t run_completed_baseline{};
        bool failure_recovery_ready{};

        void add_path(std::string path)
        {
            if (path.empty())
            {
                ui_error = "The path is empty.";
                return;
            }
            try
            {
                if (input_index_generation != queue_generation)
                {
                    std::unordered_set<std::string> refreshed;
                    refreshed.reserve(queue.size());
                    refreshed.insert(queue.begin(), queue.end());
                    input_index = std::move(refreshed);
                    input_index_generation = queue_generation;
                }
                if (input_index.contains(path))
                {
                    return;
                }
            }
            catch (const std::bad_alloc&)
            {
                ui_error = "input_memory";
                return;
            }
            catch (const std::length_error&)
            {
                ui_error = "input_capacity";
                return;
            }
            // CONTRACT: Input roots have a live RAM/commit admission budget, not
            // a fixed count ceiling. The core separately admits the full plan.
            const auto now = std::chrono::steady_clock::now();
            if (input_admission_sampled == std::chrono::steady_clock::time_point{} ||
                now - input_admission_sampled >= std::chrono::milliseconds(250))
            {
                MEMORYSTATUSEX memory{};
                memory.dwLength = static_cast<DWORD>(sizeof(memory));
                if (!GlobalMemoryStatusEx(&memory))
                {
                    ui_error = "Input memory availability could not be checked.";
                    return;
                }
                input_admission_remaining = (std::min)(memory.ullAvailPhys, memory.ullAvailPageFile) / 8;
                input_admission_sampled = now;
            }
            constexpr std::uint64_t input_overhead = sizeof(std::string) * 2 + 128;
            const auto text_bytes = static_cast<std::uint64_t>(path.size());
            if (text_bytes > ((std::numeric_limits<std::uint64_t>::max)() - input_overhead) / 2 ||
                text_bytes * 2 + input_overhead > input_admission_remaining || queue.size() == queue.max_size())
            {
                ui_error = "Insufficient memory for more input paths. Existing inputs were retained.";
                return;
            }
            const auto preceding_count = queue.size();
            try
            {
                queue.push_back(std::move(path));
                if (!input_index.insert(queue.back()).second)
                {
                    queue.pop_back();
                    return;
                }
            }
            catch (const std::bad_alloc&)
            {
                if (queue.size() != preceding_count)
                {
                    queue.pop_back();
                }
                ui_error = "input_memory";
                return;
            }
            catch (const std::length_error&)
            {
                if (queue.size() != preceding_count)
                {
                    queue.pop_back();
                }
                ui_error = "input_capacity";
                return;
            }
            input_admission_remaining -= text_bytes * 2 + input_overhead;
            ++queue_generation;
            input_index_generation = queue_generation;
            irreversible = false;
            confirmation.reset();
            downgrade_tokens.clear();
            force_process.reset();
            force_confirmation.reset();
        }
    };

    void reconcile_queue(application_state& state, const frontend::view_state& view)
    {
        bool changed{};
        if (state.queue_execution && state.queue_execution->paged_quick)
        {
            const auto& proof = view.quick_completed_inputs;
            changed = reconcile_paged_queue_report(state.queue_execution, state.queue, state.queue_generation,
                view.report, view.busy, view.executing, static_cast<bool>(proof),
                proof ? std::string_view(proof->job_id) : std::string_view{},
                proof ? std::string_view(proof->fingerprint) : std::string_view{},
                proof ? std::span<const std::string>(proof->paths) : std::span<const std::string>{});
        }
        else
        {
            changed = reconcile_queue_report(state.queue_execution, state.queue, state.queue_generation,
                view.report, view.busy, view.executing);
        }
        if (changed)
        {
            state.irreversible = false;
            state.downgrade_tokens.clear();
            state.confirmation.reset();
            state.preview_fingerprint.clear();
            state.preview_generation = state.queue_generation - 1;
            state.selected_target = 0;
            state.selected_input.reset();
            state.input_page = 0;
            state.input_admission_sampled = {};
            std::unordered_set<std::string>{}.swap(state.input_index);
            state.input_index_generation = state.queue_generation - 1;
        }
    }

    bool create_render_target(application_state& state)
    {
        ComPtr<ID3D11Texture2D> buffer;
        const HRESULT acquired = state.swap_chain->GetBuffer(0, IID_PPV_ARGS(buffer.GetAddressOf()));
        if (FAILED(acquired))
        {
            return false;
        }
        return SUCCEEDED(state.device->CreateRenderTargetView(buffer.Get(), nullptr,
            state.render_target.ReleaseAndGetAddressOf()));
    }

    bool create_graphics(application_state& state)
    {
        DXGI_SWAP_CHAIN_DESC description{};
        description.BufferCount = 2;
        description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        description.OutputWindow = state.window;
        description.SampleDesc.Count = 1;
        description.Windowed = TRUE;
        description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        constexpr std::array<D3D_FEATURE_LEVEL, 3> levels{
            D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0};
        D3D_FEATURE_LEVEL selected{};
        // INVARIANT: The D3D debug layer is never requested in this Release product.
        HRESULT created = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE,
            nullptr, 0, levels.data(), static_cast<UINT>(levels.size()), D3D11_SDK_VERSION,
            &description, state.swap_chain.GetAddressOf(), state.device.GetAddressOf(),
            &selected, state.context.GetAddressOf());
        if (FAILED(created))
        {
            state.swap_chain.Reset();
            state.device.Reset();
            state.context.Reset();
            created = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP,
                nullptr, 0, levels.data(), static_cast<UINT>(levels.size()), D3D11_SDK_VERSION,
                &description, state.swap_chain.GetAddressOf(), state.device.GetAddressOf(),
                &selected, state.context.GetAddressOf());
        }
        return SUCCEEDED(created) && create_render_target(state);
    }

    void choose_paths(application_state& state, bool folders)
    {
        ComPtr<IFileOpenDialog> dialog;
        HRESULT status = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(dialog.GetAddressOf()));
        if (FAILED(status))
        {
            state.ui_error = "file_dialog_creation_failed: " + std::to_string(status);
            return;
        }
        FILEOPENDIALOGOPTIONS options{};
        status = dialog->GetOptions(&options);
        if (SUCCEEDED(status))
        {
            options |= FOS_ALLOWMULTISELECT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST |
                FOS_DONTADDTORECENT | FOS_NODEREFERENCELINKS;
            options |= folders ? FOS_PICKFOLDERS : FOS_FILEMUSTEXIST;
            status = dialog->SetOptions(options);
        }
        if (SUCCEEDED(status))
        {
            status = dialog->SetTitle(folders ? L"Add folders to the erase queue" : L"Add files to the erase queue");
        }
        if (SUCCEEDED(status))
        {
            status = dialog->Show(state.window);
        }
        if (status == HRESULT_FROM_WIN32(ERROR_CANCELLED))
        {
            return;
        }
        ComPtr<IShellItemArray> selected;
        if (SUCCEEDED(status))
        {
            status = dialog->GetResults(selected.GetAddressOf());
        }
        DWORD count{};
        if (SUCCEEDED(status))
        {
            status = selected->GetCount(&count);
        }
        if (FAILED(status))
        {
            state.ui_error = "file_dialog_failed: " + std::to_string(status);
            return;
        }
        for (DWORD index = 0; index < count; ++index)
        {
            ComPtr<IShellItem> item;
            PWSTR raw_path{};
            status = selected->GetItemAt(index, item.GetAddressOf());
            if (SUCCEEDED(status))
            {
                status = item->GetDisplayName(SIGDN_FILESYSPATH, &raw_path);
            }
            if (FAILED(status) || raw_path == nullptr)
            {
                state.ui_error = "selected_item_has_no_filesystem_path";
                continue;
            }
            auto path = frontend::utf8(raw_path);
            CoTaskMemFree(raw_path);
            if (!path)
            {
                state.ui_error = path.error().code;
                continue;
            }
            state.add_path(std::move(*path));
        }
    }

    std::uint64_t target_size(const engine::target_snapshot& target)
    {
        std::uint64_t bytes{};
        for (const auto& stream : target.streams)
        {
            if (stream.size > (std::numeric_limits<std::uint64_t>::max)() - bytes)
            {
                return (std::numeric_limits<std::uint64_t>::max)();
            }
            bytes += stream.size;
        }
        return bytes;
    }

    void text_wrapped(const std::string& text)
    {
        ImGui::PushTextWrapPos();
        ImGui::TextUnformatted(text.c_str());
        ImGui::PopTextWrapPos();
    }

    int list_page(std::string_view id, std::size_t total, std::size_t& offset)
    {
        // CONTRACT: ImGui accepts int row counts. Paging keeps larger admitted
        // collections reachable without a hidden target-count cutoff.
        constexpr auto page_size = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (offset >= total)
        {
            offset = 0;
        }
        if (total > page_size)
        {
            ImGui::PushID(id.data(), id.data() + id.size());
            ImGui::BeginDisabled(offset == 0);
            if (ImGui::SmallButton("Previous page"))
            {
                offset = offset < page_size ? 0 : offset - page_size;
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::BeginDisabled(total - offset <= page_size);
            if (ImGui::SmallButton("Next page"))
            {
                offset += page_size;
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::Text("%zu - %zu / %zu", offset + 1, offset + (std::min)(total - offset, page_size), total);
            ImGui::PopID();
        }
        return static_cast<int>((std::min)(total - offset, page_size));
    }

    bool resource_limits_valid(const application_state& state)
    {
        return state.quick_mode || (state.max_device_workers >= 1 && state.max_device_workers <= 16 &&
            state.memory_budget_mib >= 2 && state.memory_budget_mib <= 8192 &&
            state.ssd_queue_depth >= 1 && state.ssd_queue_depth <= 4 &&
            state.io_budget_mib >= 0 && state.io_budget_mib <= 65536);
    }

    engine::options execution_settings(const application_state& state)
    {
        engine::options settings;
        settings.max_device_workers = static_cast<std::size_t>(state.max_device_workers);
        if (!state.quick_mode)
        {
            settings.memory_budget_bytes = static_cast<std::size_t>(state.memory_budget_mib) * 1024 * 1024;
            settings.ssd_queue_depth = static_cast<std::size_t>(state.ssd_queue_depth);
            settings.io_budget_bytes_per_second = static_cast<std::uint64_t>(state.io_budget_mib) * 1024 * 1024;
        }
        return settings;
    }

    void invalidate_confirmation(application_state& state)
    {
        state.irreversible = false;
        state.downgrade_tokens.clear();
        state.confirmation.reset();
        state.force_process.reset();
        state.force_job.clear();
        state.force_confirmation.reset();
    }

    bool selectable_path(const std::string& path, bool selected)
    {
        const ImVec2 position = ImGui::GetCursorScreenPos();
        const bool pressed = ImGui::Selectable("##path_selection", selected);
        ImGui::SetCursorScreenPos(position);
        ImGui::TextUnformatted(path.c_str());
        return pressed;
    }

    void render_target_preview(application_state& state, const engine::frozen_plan& plan, bool quick_mode)
    {
        const int visible_targets = list_page("target_pages", plan.targets.size(), state.target_page);
        if (ImGui::BeginTable("frozen_targets", quick_mode ? 2 : 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY, ImVec2(0, 220)))
        {
            ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 3.5F);
            ImGui::TableSetupColumn("Mode", ImGuiTableColumnFlags_WidthStretch, 1.4F);
            if (!quick_mode)
            {
                ImGui::TableSetupColumn("Allow downgrade", ImGuiTableColumnFlags_WidthStretch, 1.2F);
            }
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(visible_targets);
            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                {
                    const auto index = state.target_page + static_cast<std::size_t>(row);
                    const auto& target = plan.targets[index];
                    ImGui::PushID(row);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (selectable_path(target.path, state.selected_target == index))
                    {
                        state.selected_target = index;
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(quick_mode ?
                        (target.support == engine::capability::blocked ? "Unavailable" : "Quick delete") :
                        frontend::capability_name(target.support).data());
                    if (!quick_mode)
                    {
                        ImGui::TableSetColumnIndex(2);
                    }
                    if (!quick_mode && engine::needs_downgrade(target))
                    {
                        const auto token = frontend::downgrade_token(target);
                        bool approved = state.downgrade_tokens.contains(token);
                        if (ImGui::Checkbox("Allow##downgrade", &approved))
                        {
                            if (approved)
                            {
                                state.downgrade_tokens.insert(token);
                            }
                            else
                            {
                                state.downgrade_tokens.erase(token);
                            }
                        }
                    }
                    else if (!quick_mode)
                    {
                        ImGui::TextDisabled("--");
                    }
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }
        if (state.selected_target < plan.targets.size() && ImGui::CollapsingHeader("Selected target details"))
        {
            const auto& target = plan.targets[state.selected_target];
            text_wrapped(target.path);
            if (!quick_mode)
            {
                ImGui::Text("%llu bytes | %s | %zu streams | %u hard links | %u other names retained",
                    static_cast<unsigned long long>(target_size(target)), frontend::media_name(target.media).data(),
                    target.streams.size(), target.link_count, target.link_count > 1 ? target.link_count - 1 : 0);
                ImGui::Text("Reparse %s | compressed %s | sparse %s | encrypted %s",
                    target.reparse_point ? "yes" : "no", target.compressed ? "yes" : "no",
                    target.sparse ? "yes" : "no", target.encrypted ? "yes" : "no");
                ImGui::Text("VSS %s | snapshots %u | native %u",
                    target.vss_query_complete ? "complete" : "unknown", target.vss_snapshot_count, target.vss_native_error);
            }
            for (const auto& risk : target.residual_risks)
            {
                text_wrapped(risk);
            }
            for (const auto& reason : target.protection_reasons)
            {
                text_wrapped(reason);
            }
        }
    }

    void render_quick_page(application_state& state, const frontend::view_state& view, bool failures_only)
    {
        if (!view.quick_paged || !view.plan)
        {
            return;
        }
        auto& cursor = failures_only ? state.quick_failure_cursor : state.quick_preview_cursor;
        auto& history = failures_only ? state.quick_failure_history : state.quick_preview_history;
        const auto& page = view.quick_page_data;
        const auto matching = [&]()
        {
            return page && page->job_id == view.plan->job_id && page->fingerprint == view.plan->fingerprint &&
                page->offset == cursor && page->failures_only == failures_only;
        };
        const auto invalidate_page = [&]()
        {
            state.page_request.reset();
            if (failures_only)
            {
                state.selected_failure_path.clear();
                state.force_process.reset();
                state.force_confirmation.reset();
            }
        };
        ImGui::PushID(failures_only ? "incomplete_page" : "preview_page");
        ImGui::BeginDisabled(cursor == 0);
        if (ImGui::SmallButton("First"))
        {
            cursor = 0;
            history.clear();
            invalidate_page();
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(history.empty());
        if (ImGui::SmallButton("Previous"))
        {
            cursor = history.back();
            history.pop_back();
            invalidate_page();
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        const bool next = matching() && page->next_offset > cursor && page->next_offset < view.quick_total;
        ImGui::BeginDisabled(!next);
        if (ImGui::SmallButton("Next"))
        {
            try
            {
                history.push_back(cursor);
                cursor = page->next_offset;
                invalidate_page();
            }
            catch (const std::bad_alloc&)
            {
                state.ui_error = "page_memory";
            }
        }
        ImGui::EndDisabled();
        if (!matching())
        {
            const bool requested = state.page_request && state.page_request->job_id == view.plan->job_id &&
                state.page_request->fingerprint == view.plan->fingerprint && state.page_request->cursor == cursor &&
                state.page_request->failures_only == failures_only;
            if (!view.quick_page_loading && !requested)
            {
                state.page_request = page_request_binding{view.plan->job_id, view.plan->fingerprint, cursor, failures_only};
                if (!state.app.request_quick_page(cursor, failures_only))
                {
                    state.ui_error = "page_not_started";
                }
            }
            ImGui::TextDisabled(view.quick_page_loading ? "Loading targets..." : "Target page is not available yet.");
            if (!view.quick_page_loading && requested && ImGui::SmallButton("Retry page"))
            {
                state.page_request.reset();
            }
            ImGui::PopID();
            return;
        }
        // SECURITY: Page metadata is bound to this exact plan. Empty items never
        // certify completion, and source cursors do not count filtered results.
        if (page->items.size() > 128 || page->next_offset < page->offset || page->next_offset > view.quick_total)
        {
            ImGui::TextUnformatted("Target page binding is invalid.");
            ImGui::PopID();
            return;
        }
        ImGui::SameLine();
        ImGui::Text("Showing %zu targets | Total %llu", page->items.size(), static_cast<unsigned long long>(page->total));
        if (page->items.empty())
        {
            ImGui::TextDisabled("No matching rows on this page.");
        }
        if (ImGui::BeginTable("paged_targets", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY, ImVec2(0, 210)))
        {
            ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthStretch, 3.0F);
            ImGui::TableSetupColumn(failures_only ? "Result" : "Mode", ImGuiTableColumnFlags_WidthStretch, 1.5F);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(page->items.size()));
            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                {
                    const auto& item = page->items[static_cast<std::size_t>(row)];
                    ImGui::PushID(row);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    const bool selected = failures_only ? state.selected_failure_path == item.target.path :
                        state.selected_target == item.index;
                    if (selectable_path(item.target.path, selected))
                    {
                        if (failures_only)
                        {
                            state.selected_failure_path = item.target.path;
                            state.force_process.reset();
                            state.force_confirmation.reset();
                        }
                        else
                        {
                            state.selected_target = static_cast<std::size_t>(item.index);
                        }
                    }
                    if (ImGui::IsItemHovered() && item.outcome)
                    {
                        ImGui::SetTooltip("%s | native %u", item.outcome->code.c_str(), item.outcome->native_code);
                    }
                    ImGui::TableSetColumnIndex(1);
                    if (item.outcome)
                    {
                        ImGui::TextUnformatted(item.outcome->code.c_str());
                    }
                    else
                    {
                        ImGui::TextUnformatted(item.target.preparation_error.code.empty() ? "Quick delete" : "Unavailable");
                    }
                    ImGui::PopID();
                }
            }
            ImGui::EndTable();
        }
        ImGui::PopID();
    }

    void render_preview(application_state& state, const frontend::view_state& view)
    {
        if (state.preparation_requested)
        {
            if (state.preparation_just_started)
            {
                state.preparation_just_started = false;
                return;
            }
            if (view.busy)
            {
                return;
            }
            state.preparation_requested = false;
            if (view.plan && (state.retry_requested || view.error_code.empty()) && view.quick_mode == state.quick_mode &&
                (view.resume_loaded || state.retry_requested || state.preview_generation == state.queue_generation))
            {
                invalidate_confirmation(state);
                state.preview_fingerprint = view.plan->fingerprint;
                state.confirmation = confirmation_binding{view.plan->job_id, view.plan->fingerprint,
                    state.queue_generation, view.quick_mode};
                state.selected_target = 0;
                state.target_page = 0;
                state.quick_preview_cursor = 0;
                state.quick_preview_history.clear();
                state.page_request.reset();
                state.confirmation_visible = true;
                ImGui::OpenPopup("Confirm batch");
            }
        }
        ImGui::SetNextWindowSize(ImVec2(820, 0), ImGuiCond_Appearing);
        if (ImGui::BeginPopupModal("Confirm batch", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
        {
            const bool current_plan = confirmation_matches(state.confirmation, view.plan,
                state.queue_generation, view.quick_mode) && state.quick_mode == view.quick_mode;
            if (!current_plan)
            {
                ImGui::TextWrapped("The queue or plan changed. Go back and start again.");
            }
            else
            {
                ImGui::Text("%s | %zu frozen targets", view.quick_mode ? "Quick delete" : "Overwrite and verify",
                    view.quick_paged ? view.quick_total : view.plan->targets.size());
                ImGui::TextWrapped("Only these frozen targets are eligible. New or replaced objects are excluded.");
                if (view.quick_mode)
                {
                    ImGui::TextWrapped(state.retry_requested ?
                        "Retry only incomplete targets from this original job. No recycle bin or overwriting." :
                        "Permanently delete names without overwriting. Access and lock recovery follow the first pass.");
                    if (ImGui::CollapsingHeader("Review frozen targets"))
                    {
                        if (view.quick_paged)
                        {
                            render_quick_page(state, view, false);
                        }
                        else
                        {
                            render_target_preview(state, *view.plan, true);
                        }
                    }
                }
                else
                {
                    ImGui::TextWrapped("Approve each reduced guarantee separately. SSD, snapshot and backup remnants may remain.");
                    render_target_preview(state, *view.plan, false);
                }
                ImGui::Checkbox("I confirm irreversible changes or deletion of these targets.", &state.irreversible);
            }
            const bool can_execute = current_plan && !view.busy && !state.exit_requested &&
                resource_limits_valid(state) && state.irreversible;
            ImGui::BeginDisabled(!can_execute);
            if (ImGui::Button("Confirm and start", ImVec2(140, 0)))
            {
                auto queue_binding = bind_queue_run(state.queue_execution, view.plan, view.report,
                    view.resume_loaded || state.retry_requested, state.queue, state.queue_generation,
                    state.preview_generation, view.quick_mode, view.quick_paged);
                std::vector<std::string> tokens(state.downgrade_tokens.begin(), state.downgrade_tokens.end());
                bool accepted{};
                const bool configured = view.quick_mode ? state.app.configure_quick({}) :
                    state.app.configure_execution(execution_settings(state));
                if (configured)
                {
                    if (view.quick_mode)
                    {
                        accepted = state.retry_requested ?
                            state.app.retry_quick(state.confirmation->fingerprint, true) :
                            state.app.execute_quick(state.confirmation->fingerprint, true);
                    }
                    else
                    {
                        accepted = state.app.execute(state.confirmation->fingerprint, true, std::move(tokens));
                    }
                }
                if (!accepted)
                {
                    state.ui_error = "execution_not_started";
                }
                else
                {
                    // SECURITY: Mode dispatch never submits the lightweight display plan to the overwrite engine.
                    state.queue_execution = std::move(queue_binding);
                    state.last_run_plan = view.plan;
                    state.last_run_quick = view.quick_mode;
                    state.run_started = std::chrono::steady_clock::now();
                    state.run_completed_baseline = view.quick_mode && state.retry_requested ? view.completed_count : 0;
                }
                invalidate_confirmation(state);
                state.confirmation_visible = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Button("Back", ImVec2(100, 0)))
            {
                invalidate_confirmation(state);
                state.confirmation_visible = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    void render_queue(application_state& state, const frontend::view_state& view)
    {
        ImGui::BeginDisabled(view.busy || state.exit_requested || state.confirmation_visible ||
            state.preparation_requested);
        ImGui::TextUnformatted("Mode");
        ImGui::SameLine();
        if (ImGui::RadioButton("Quick delete", state.quick_mode))
        {
            if (!state.quick_mode)
            {
                state.quick_mode = true;
                if (state.input_index_generation == state.queue_generation)
                {
                    ++state.input_index_generation;
                }
                ++state.queue_generation;
                invalidate_confirmation(state);
            }
        }
        ImGui::SameLine();
        if (ImGui::RadioButton("Overwrite and verify", !state.quick_mode))
        {
            if (state.quick_mode)
            {
                state.quick_mode = false;
                if (state.input_index_generation == state.queue_generation)
                {
                    ++state.input_index_generation;
                }
                ++state.queue_generation;
                invalidate_confirmation(state);
            }
        }
        ImGui::TextDisabled(state.quick_mode ? "Automatic scheduling. No recycle bin or content overwrite." :
            "Overwrite, flush and fully verify. Reduced guarantees require separate consent.");
        ImGui::SetNextItemWidth(-86.0F);
        const bool path_entered = ImGui::InputTextWithHint("##path", "Add an absolute file or folder path, or drag it here",
            state.typed_path.data(), state.typed_path.size(), ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if (ImGui::Button("Add path") || path_entered)
        {
            auto valid = frontend::utf16(state.typed_path.data());
            if (valid)
            {
                state.add_path(state.typed_path.data());
                state.typed_path.fill('\0');
            }
            else
            {
                state.ui_error = valid.error().code;
            }
        }
        if (ImGui::Button("Add files"))
        {
            choose_paths(state, false);
        }
        ImGui::SameLine();
        if (ImGui::Button("Add folders"))
        {
            choose_paths(state, true);
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(!state.selected_input || *state.selected_input >= state.queue.size());
        if (ImGui::Button("Remove selected"))
        {
            if (state.input_index_generation == state.queue_generation)
            {
                state.input_index.erase(state.queue[*state.selected_input]);
                ++state.input_index_generation;
            }
            state.queue.erase(state.queue.begin() + static_cast<std::ptrdiff_t>(*state.selected_input));
            state.selected_input.reset();
            ++state.queue_generation;
            invalidate_confirmation(state);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(state.queue.empty());
        if (ImGui::Button("Clear list"))
        {
            state.queue.clear();
            std::unordered_set<std::string>{}.swap(state.input_index);
            state.selected_input.reset();
            ++state.queue_generation;
            state.input_index_generation = state.queue_generation;
            state.input_admission_sampled = {};
            invalidate_confirmation(state);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextDisabled("Drag files or folders here");
        const int visible_inputs = list_page("input_pages", state.queue.size(), state.input_page);
        const float queue_height = (std::clamp)(ImGui::GetContentRegionAvail().y - 190.0F, 120.0F, 340.0F);
        if (ImGui::BeginChild("input_queue", ImVec2(0, queue_height), ImGuiChildFlags_Borders))
        {
            if (state.queue.empty())
            {
                ImGui::TextDisabled("Add the files and folders you want to process.");
            }
            ImGuiListClipper clipper;
            clipper.Begin(visible_inputs);
            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                {
                    ImGui::PushID(row);
                    const auto index = state.input_page + static_cast<std::size_t>(row);
                    if (selectable_path(state.queue[index], state.selected_input == index))
                    {
                        state.selected_input = index;
                    }
                    ImGui::PopID();
                }
            }
        }
        ImGui::EndChild();
        ImGui::Text("%zu input paths", state.queue.size());
        ImGui::SameLine();
        ImGui::BeginDisabled(state.queue.empty() || !resource_limits_valid(state));
        if (ImGui::Button("Start", ImVec2(140, 0)))
        {
            invalidate_confirmation(state);
            state.preview_generation = state.queue_generation;
            state.retry_requested = false;
            const bool prepared = state.quick_mode ? state.app.preview_quick(state.queue) : state.app.preview(state.queue);
            if (!prepared)
            {
                state.ui_error = "preparation_not_started";
            }
            else
            {
                state.preparation_requested = true;
                state.preparation_just_started = true;
            }
        }
        ImGui::EndDisabled();
        ImGui::EndDisabled();
    }

    void render_progress(application_state& state, const frontend::view_state& view)
    {
        if (view.busy && !view.executing)
        {
            ImGui::TextUnformatted(state.preparation_requested ? "Preparing the fixed target list..." : "Working...");
            if (state.preparation_requested && view.quick_mode)
            {
                ImGui::SameLine();
                if (ImGui::Button("Cancel preparation"))
                {
                    state.app.cancel();
                    state.preparation_requested = false;
                    invalidate_confirmation(state);
                }
            }
        }
        if (view.executing || view.report)
        {
            if (view.quick_mode)
            {
                ImGui::Text("Completed %zu | Failed %zu | Pending %zu", view.completed_count, view.failed_count, view.quick_pending);
                if (view.quick_statistics.supported)
                {
                    const auto& statistics = view.quick_statistics;
                    const auto counts = std::format("Files {} / {} | Directories {} / {} | Unclassified {}",
                        statistics.completed.files, statistics.selected.files,
                        statistics.completed.directories, statistics.selected.directories,
                        statistics.selected.unclassified);
                    ImGui::TextUnformatted(counts.c_str());
                    const auto bytes = std::format("Removed snapshot logical bytes: {} | Unknown sizes: {}",
                        statistics.logical_bytes.completed, statistics.logical_bytes.completed_unknown);
                    ImGui::TextDisabled("%s", bytes.c_str());
                    if (ImGui::IsItemHovered())
                    {
                        ImGui::SetTooltip("Known default-stream lengths captured before deletion. This is neither allocated space nor an attributable free-space increase.");
                    }
                }
            }
            else
            {
                ImGui::Text("Completed %zu | Incomplete %zu", view.completed_count, view.failed_count);
            }
        }
        if (view.executing)
        {
            if (view.quick_mode)
            {
                const float fraction = view.quick_total == 0 ? 0.0F : static_cast<float>((std::min)(1.0,
                    static_cast<double>(view.quick_attempted) / static_cast<double>(view.quick_total)));
                const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() -
                    state.run_started).count();
                const auto completed = view.completed_count > state.run_completed_baseline ?
                    view.completed_count - state.run_completed_baseline : 0;
                const double rate = seconds > 0.0 ? static_cast<double>(completed) / seconds : 0.0;
                ImGui::TextUnformatted(view.quick_stage == "recovery" ? "Final phase: recovering failed targets" : "Deleting names");
                ImGui::ProgressBar(fraction, ImVec2(-1, 0));
                ImGui::Text("Attempted %zu / %zu | Average %.1f deletions/s", view.quick_attempted, view.quick_total, rate);
            }
            else
            {
                std::uint64_t done{};
                std::uint64_t total{};
                double speed{};
                for (const auto& device : view.devices)
                {
                    const auto maximum = (std::numeric_limits<std::uint64_t>::max)();
                    done = device.transferred_bytes > maximum - done ? maximum : done + device.transferred_bytes;
                    total = device.total_bytes > maximum - total ? maximum : total + device.total_bytes;
                    speed += device.bytes_per_second;
                }
                const float fraction = total == 0 ? 0.0F : static_cast<float>((std::min)(1.0,
                    static_cast<double>(done) / static_cast<double>(total)));
                ImGui::ProgressBar(fraction, ImVec2(-1, 0));
                ImGui::Text("%.1f MiB/s", speed / 1048576.0);
            }
            if (ImGui::Button("Pause"))
            {
                state.app.pause();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel remaining"))
            {
                state.app.cancel();
            }
        }
        else if (!view.busy && !view.quick_mode && view.report && view.report->status == "paused")
        {
            if (ImGui::Button("Load and continue"))
            {
                if (state.app.load_job(view.report->job_id))
                {
                    invalidate_confirmation(state);
                    state.quick_mode = false;
                    state.retry_requested = false;
                    state.preparation_requested = true;
                    state.preparation_just_started = true;
                }
                else
                {
                    state.ui_error = "resume_not_started";
                }
            }
        }
        const auto failure = frontend::diagnostic_failure(view);
        if (!failure.code.empty())
        {
            ImGui::TextColored(ImVec4(1.0F, 0.55F, 0.35F, 1.0F), "%s | native %u",
                failure.code.c_str(), failure.native_code);
            if (frontend::diagnostic_failure_kind(failure.code, failure.native_code) == "safety_refusal")
            {
                if (failure.code == "running_image" || failure.code == "running_image_ancestor" ||
                    failure.code == "quick_running_image" || failure.code == "quick_running_image_ancestor")
                {
                    ImGui::TextWrapped("The running program and any selected directory containing it are protected. Run the tool from a separate directory before cleaning this location.");
                }
                else
                {
                    ImGui::TextWrapped("Safety policy refused a protected resource. Review the selected target and the copied diagnostic code.");
                }
            }
        }
        if (!failure.code.empty() || (view.report && !view.busy && view.report->status != "completed"))
        {
            if (ImGui::Button("Copy failure diagnostics JSON"))
            {
                const auto diagnostics = state.app.diagnostics(state.report_page);
                ImGui::SetClipboardText(diagnostics.c_str());
            }
        }
    }

    void render_diagnostics(application_state& state, const frontend::view_state& view)
    {
        ImGui::Text("State: %s", view.status.c_str());
        if (!view.error_code.empty())
        {
            ImGui::Text("Error: %s | native %u", view.error_code.c_str(), view.native_code);
        }
        for (const auto& device : view.devices)
        {
            ImGui::Text("Device %s | %llu/%llu bytes | %.2f MiB/s | ETA %.1f s",
                device.device_key.c_str(), static_cast<unsigned long long>(device.transferred_bytes),
                static_cast<unsigned long long>(device.total_bytes), device.bytes_per_second / 1048576.0,
                device.eta_seconds);
        }
        if (ImGui::Button("Copy diagnostics JSON"))
        {
            const auto diagnostics = state.app.diagnostics(state.report_page);
            ImGui::SetClipboardText(diagnostics.c_str());
        }
        ImGui::TextDisabled("Masked summary: at most 128 outcomes and 64 recent events; paging and retained-log location are included.");
        if (view.report)
        {
            ImGui::Text("Job: %s | %s", view.report->job_id.c_str(), view.report->status.c_str());
            if (view.quick_paged)
            {
                ImGui::TextDisabled("Full quick outcomes are paged in this live session. Retained logs contain failures and lifecycle counts.");
            }
            else
            {
                const int visible_outcomes = list_page("outcome_pages", view.report->targets.size(), state.report_page);
                if (ImGui::BeginChild("raw_outcomes", ImVec2(0, 160), ImGuiChildFlags_Borders))
                {
                    ImGuiListClipper clipper;
                    clipper.Begin(visible_outcomes);
                    while (clipper.Step())
                    {
                        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                        {
                            const auto& outcome = view.report->targets[state.report_page + static_cast<std::size_t>(row)];
                            ImGui::Text("%s | %s | deleted %s | verified %s | native %u", outcome.identity.c_str(),
                                outcome.code.c_str(), outcome.deleted ? "yes" : "no",
                                outcome.logical_overwrite_verified ? "yes" : "no", outcome.native_code);
                        }
                    }
                }
                ImGui::EndChild();
            }
        }
        if (ImGui::BeginChild("events", ImVec2(0, 150), ImGuiChildFlags_Borders))
        {
            for (const auto& event : view.recent_events)
            {
                ImGui::Text("%s | %s | %llu/%llu | native %u", event.code.c_str(), event.identity.c_str(),
                    static_cast<unsigned long long>(event.bytes_done),
                    static_cast<unsigned long long>(event.bytes_total), event.native_code);
            }
        }
        ImGui::EndChild();
        static_cast<void>(state);
    }

    void render_history(application_state& state, const frontend::view_state& view)
    {
        ImGui::BeginDisabled(view.busy || state.confirmation_visible || state.exit_requested);
        if (ImGui::Button("Refresh history and saved jobs"))
        {
            if (!state.app.refresh_history())
            {
                state.ui_error = "worker_busy";
            }
        }
        for (const auto& checkpoint : view.checkpoints)
        {
            ImGui::PushID(checkpoint.job_id.c_str());
            if (ImGui::Button("Load for confirmation"))
            {
                if (state.app.load_job(checkpoint.job_id))
                {
                    invalidate_confirmation(state);
                    state.quick_mode = false;
                    state.retry_requested = false;
                    state.preparation_requested = true;
                    state.preparation_just_started = true;
                }
                else
                {
                    state.ui_error = "worker_busy";
                }
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(checkpoint.job_id.c_str());
            ImGui::PopID();
        }
        ImGui::EndDisabled();
        if (ImGui::TreeNode("JSONL history"))
        {
            if (ImGui::BeginChild("history", ImVec2(0, 160), ImGuiChildFlags_Borders,
                    ImGuiWindowFlags_HorizontalScrollbar))
            {
                ImGui::TextUnformatted(view.history.c_str());
            }
            ImGui::EndChild();
            ImGui::TreePop();
        }
    }

    bool successful_outcome(const engine::target_outcome& outcome)
    {
        return outcome.deleted && (outcome.code == "deleted_logical_overwrite_verified_residual_risk" ||
            outcome.code == "deleted_only_residual_risk" || outcome.code == "completed_from_authenticated_checkpoint" ||
            outcome.code == "deleted_quick_namespace_removed");
    }

    void refresh_failures(application_state& state, const frontend::view_state& view)
    {
        if (view.busy || view.executing || view.report == state.failure_report)
        {
            return;
        }
        state.failed_targets.clear();
        state.failed_outcomes.clear();
        state.failure_page = 0;
        state.report_page = 0;
        state.failure_recovery_ready = false;
        state.selected_failure_path.clear();
        state.force_process.reset();
        state.force_confirmation.reset();
        state.failure_report = view.report;
        if (!view.report || !state.last_run_plan || view.report->job_id != state.last_run_plan->job_id ||
            (view.quick_mode && view.report->plan_fingerprint != state.last_run_plan->fingerprint))
        {
            return;
        }
        if (view.quick_paged)
        {
            state.failure_recovery_ready = paged_manual_recovery_allowed(view.quick_total,
                view.quick_attempted, view.quick_pending);
            state.quick_failure_cursor = 0;
            state.quick_failure_history.clear();
            state.page_request.reset();
            return;
        }
        state.failure_recovery_ready = manual_recovery_allowed(*view.report, view.quick_mode);
        std::unordered_map<std::string_view, const engine::target_snapshot*> targets;
        targets.reserve(state.last_run_plan->targets.size());
        for (const auto& target : state.last_run_plan->targets)
        {
            const auto [item, inserted] = targets.emplace(target.identity, &target);
            if (!inserted)
            {
                item->second = nullptr;
            }
        }
        for (const auto& outcome : view.report->targets)
        {
            if (!successful_outcome(outcome))
            {
                const auto target = targets.find(outcome.identity);
                if (target != targets.end() && target->second != nullptr)
                {
                    state.failed_targets.emplace(target->second->path, target->second);
                    state.failed_outcomes.emplace_back(target->second, &outcome);
                }
            }
        }
    }

    bool current_failure(const application_state& state, const frontend::view_state& view,
        const std::string& path)
    {
        if (view.busy || view.executing || !view.report || view.report != state.failure_report ||
            !state.last_run_plan || view.report->job_id != state.last_run_plan->job_id ||
            state.last_run_quick != view.quick_mode || !state.failure_recovery_ready)
        {
            return false;
        }
        if (view.quick_mode && (!view.plan || view.plan->job_id != state.last_run_plan->job_id ||
            view.plan->fingerprint != state.last_run_plan->fingerprint))
        {
            return false;
        }
        if (view.quick_paged)
        {
            const auto& page = view.quick_page_data;
            if (!paged_manual_recovery_allowed(view.quick_total, view.quick_attempted, view.quick_pending) ||
                !page || !page->failures_only || page->job_id != view.report->job_id ||
                page->fingerprint != state.last_run_plan->fingerprint || page->offset != state.quick_failure_cursor)
            {
                return false;
            }
            return std::ranges::any_of(page->items, [&](const auto& item)
            {
                return item.index < view.quick_total && item.target.path == path && item.outcome &&
                    !successful_outcome(*item.outcome) && item.outcome->code != "quick_not_attempted" &&
                    item.outcome->code != "quick_device_stopped" &&
                    item.target.preparation_error.code.empty();
            });
        }
        return state.failed_targets.contains(path) &&
            state.failed_targets.at(path)->support != engine::capability::blocked;
    }

    void render_locks(application_state& state, const frontend::view_state& view)
    {
        if (state.selected_failure_path.empty() || view.lock_path != state.selected_failure_path)
        {
            return;
        }
        const bool allowed = current_failure(state, view, state.selected_failure_path) &&
            view.error_code.empty() && (view.status == "locks_ready" || view.status == "quick_locks_ready");
        ImGui::SeparatorText("Lock recovery after failure");
        text_wrapped(state.selected_failure_path);
        if (view.locks.empty() && !view.busy)
        {
            ImGui::TextDisabled("No identifiable locking processes found.");
        }
        for (const auto& process : view.locks)
        {
            ImGui::PushID(static_cast<int>(process.process_id));
            ImGui::Text("PID %u", process.process_id);
            ImGui::SameLine();
            text_wrapped(process.image_path);
            if (!process.eligible)
            {
                text_wrapped(process.denial_reason);
            }
            ImGui::BeginDisabled(!allowed || !process.eligible || state.exit_requested);
            if (ImGui::Button("Request normal close"))
            {
                const bool accepted = view.quick_mode ?
                    state.app.close_quick_process(state.selected_failure_path, process, false,
                        state.last_run_plan->fingerprint) :
                    state.app.close_process(state.selected_failure_path, process, false);
                if (!accepted)
                {
                    state.ui_error = "close_not_started";
                }
                else
                {
                    state.selected_failure_path.clear();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Review force termination"))
            {
                state.force_process = process;
                state.force_path = state.selected_failure_path;
                state.force_job = state.last_run_plan->job_id;
                state.force_confirmation = confirmation_binding{state.last_run_plan->job_id,
                    state.last_run_plan->fingerprint, state.queue_generation, view.quick_mode};
                ImGui::OpenPopup("Confirm one process termination");
            }
            ImGui::EndDisabled();
            if (ImGui::BeginPopupModal("Confirm one process termination", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
            {
                const bool current = allowed && state.force_process &&
                    confirmation_matches(state.force_confirmation, state.last_run_plan,
                        state.queue_generation, view.quick_mode) &&
                    current_failure(state, view, state.force_path) && state.force_job == view.report->job_id;
                if (state.force_process)
                {
                    ImGui::Text("PID %u | created %llu", state.force_process->process_id,
                        static_cast<unsigned long long>(state.force_process->creation_time));
                    text_wrapped(state.force_process->image_path);
                }
                ImGui::TextWrapped("Only this revalidated process is authorized. Unsaved data may be lost.");
                ImGui::BeginDisabled(!current || state.exit_requested);
                if (ImGui::Button("Terminate this process"))
                {
                    const bool accepted = view.quick_mode ?
                        state.app.close_quick_process(state.force_path, *state.force_process, true,
                            state.force_confirmation->fingerprint) :
                        state.app.close_process(state.force_path, *state.force_process, true);
                    if (!accepted)
                    {
                        state.ui_error = "force_close_not_started";
                    }
                    state.force_process.reset();
                    state.force_confirmation.reset();
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndDisabled();
                ImGui::SameLine();
                if (ImGui::Button("Back"))
                {
                    state.force_process.reset();
                    state.force_confirmation.reset();
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }

    void render_failures(application_state& state, const frontend::view_state& view)
    {
        if (!view.report || view.executing || view.report != state.failure_report)
        {
            return;
        }
        const auto incomplete = view.quick_paged ? view.quick_total - (std::min)(view.quick_total, view.completed_count) :
            state.failed_outcomes.size();
        if (incomplete != 0)
        {
            ImGui::BeginDisabled(view.busy);
            if (ImGui::Button("Review incomplete targets"))
            {
                state.failure_popup_open = true;
                ImGui::OpenPopup("Incomplete targets");
            }
            ImGui::EndDisabled();
        }
        if (view.quick_mode && view.plan && incomplete != 0 && view.report->status != "completed")
        {
            if (incomplete != 0)
            {
                ImGui::SameLine();
            }
            ImGui::BeginDisabled(view.busy || state.confirmation_visible || state.exit_requested);
            if (ImGui::Button(view.report->status == "paused" ? "Continue quick deletion" : "Retry this job's incomplete targets"))
            {
                invalidate_confirmation(state);
                state.quick_mode = true;
                state.retry_requested = true;
                state.preparation_requested = true;
                state.preparation_just_started = true;
            }
            ImGui::EndDisabled();
            ImGui::TextDisabled("Quick jobs exist only in this session. Retry requires fresh confirmation.");
        }
        ImGui::SetNextWindowSize(ImVec2(800, 540), ImGuiCond_Appearing);
        if (ImGui::BeginPopupModal("Incomplete targets", nullptr, ImGuiWindowFlags_NoResize))
        {
            ImGui::TextWrapped(state.failure_recovery_ready ?
                "The first pass has finished. Only incomplete frozen targets are listed." :
                "The first pass is incomplete. Continue this job before resolving locks.");
            if (view.quick_paged)
            {
                render_quick_page(state, view, true);
            }
            else
            {
                const int visible_failures = list_page("failure_pages", state.failed_outcomes.size(), state.failure_page);
                if (ImGui::BeginChild("failed_targets", ImVec2(0, 190), ImGuiChildFlags_Borders))
                {
                    ImGuiListClipper clipper;
                    clipper.Begin(visible_failures);
                    while (clipper.Step())
                    {
                        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
                        {
                            const auto& [target, outcome] = state.failed_outcomes[state.failure_page + static_cast<std::size_t>(row)];
                            ImGui::PushID(row);
                            if (selectable_path(target->path, state.selected_failure_path == target->path))
                            {
                                state.selected_failure_path = target->path;
                            }
                            if (ImGui::IsItemHovered())
                            {
                                ImGui::SetTooltip("%s | native %u", outcome->code.c_str(), outcome->native_code);
                            }
                            ImGui::PopID();
                        }
                    }
                }
                ImGui::EndChild();
            }
            const bool selected = current_failure(state, view, state.selected_failure_path);
            ImGui::BeginDisabled(!selected || state.exit_requested);
            if (ImGui::Button("Inspect locks for selected failure"))
            {
                const bool accepted = view.quick_mode ?
                    state.app.query_quick_locks(state.selected_failure_path, state.last_run_plan->fingerprint) :
                    state.app.query_locks(state.selected_failure_path);
                if (!accepted)
                {
                    state.ui_error = "lock_query_not_started";
                }
            }
            ImGui::EndDisabled();
            render_locks(state, view);
            if (ImGui::Button("Close"))
            {
                state.force_process.reset();
                state.force_confirmation.reset();
                state.failure_popup_open = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

    void render_advanced(application_state& state, const frontend::view_state& view)
    {
        state.details_open = ImGui::CollapsingHeader("Details");
        if (!state.details_open)
        {
            return;
        }
        if (!state.quick_mode && ImGui::TreeNode("Overwrite resource limits"))
        {
            ImGui::BeginDisabled(view.busy || state.confirmation_visible);
            ImGui::InputInt("Device workers (1..16)", &state.max_device_workers);
            ImGui::InputInt("Memory MiB (2..8192)", &state.memory_budget_mib);
            ImGui::InputInt("SSD queue depth (1..4)", &state.ssd_queue_depth);
            ImGui::InputInt("I/O MiB/s (0 = unlimited)", &state.io_budget_mib);
            ImGui::EndDisabled();
            ImGui::TreePop();
        }
        if (ImGui::TreeNode("Recovery and history"))
        {
            render_history(state, view);
            ImGui::TreePop();
        }
        if (ImGui::TreeNode("Diagnostics and JSON report"))
        {
            render_diagnostics(state, view);
            ImGui::TreePop();
        }
        ImGui::TextDisabled("%s | Unpublished development build", secure_erase::metadata::version());
    }

    void render(application_state& state, const frontend::view_state& view)
    {
        const auto* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        const auto flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoSavedSettings;
        ImGui::Begin("secure_erase_main", nullptr, flags);
        ImGui::TextUnformatted("Windows Agent Cleanup");
        if (state.exit_requested)
        {
            ImGui::TextColored(ImVec4(1.0F, 0.75F, 0.25F, 1.0F), "Stopping safely before closing...");
        }
        if (!state.ui_error.empty())
        {
            text_wrapped(state.ui_error);
            ImGui::SameLine();
            if (ImGui::SmallButton("Dismiss"))
            {
                state.ui_error.clear();
            }
        }
        render_queue(state, view);
        render_progress(state, view);
        render_failures(state, view);
        render_advanced(state, view);
        render_preview(state, view);
        ImGui::End();
    }

    LRESULT CALLBACK window_procedure(HWND window, UINT message, WPARAM word, LPARAM parameter)
    {
        if (message == WM_NCCREATE)
        {
            const auto* creation = reinterpret_cast<const CREATESTRUCTW*>(parameter);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(creation->lpCreateParams));
        }
        auto* state = reinterpret_cast<application_state*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (state == nullptr)
        {
            return DefWindowProcW(window, message, word, parameter);
        }
        if (state->imgui_ready && ImGui_ImplWin32_WndProcHandler(window, message, word, parameter))
        {
            return TRUE;
        }
        switch (message)
        {
        case WM_SIZE:
            state->minimized = word == SIZE_MINIMIZED;
            if (!state->minimized)
            {
                state->pending_width = static_cast<UINT>(LOWORD(parameter));
                state->pending_height = static_cast<UINT>(HIWORD(parameter));
            }
            return 0;
        case WM_GETMINMAXINFO:
        {
            auto* constraints = reinterpret_cast<MINMAXINFO*>(parameter);
            constraints->ptMinTrackSize = POINT{780, 560};
            return 0;
        }
        case WM_DROPFILES:
        {
            const HDROP drop = reinterpret_cast<HDROP>(word);
            const auto view = state->app.snapshot(false);
            reconcile_queue(*state, view);
            if (!view.busy && !state->exit_requested)
            {
                const UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
                for (UINT index = 0; index < count; ++index)
                {
                    const UINT length = DragQueryFileW(drop, index, nullptr, 0);
                    if (length == 0 || length > 32767)
                    {
                        state->ui_error = "dropped_path_length_rejected";
                        continue;
                    }
                    std::wstring wide(static_cast<std::size_t>(length) + 1, L'\0');
                    if (DragQueryFileW(drop, index, wide.data(), length + 1) != length)
                    {
                        state->ui_error = "drop_path_read_failed";
                        continue;
                    }
                    wide.resize(length);
                    auto path = frontend::utf8(wide);
                    if (path)
                    {
                        state->add_path(std::move(*path));
                    }
                    else
                    {
                        state->ui_error = path.error().code;
                    }
                }
            }
            DragFinish(drop);
            return 0;
        }
        case WM_CLOSE:
            state->exit_requested = true;
            state->app.cancel();
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        case WM_SYSCOMMAND:
            if ((word & 0xFFF0) == SC_KEYMENU)
            {
                return 0;
            }
            break;
        default:
            break;
        }
        return DefWindowProcW(window, message, word, parameter);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_mode)
{
    // CONTRACT: UI uses one STA and one native window; worker threads never call ImGui.
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(com))
    {
        MessageBoxW(nullptr, L"COM initialization failed.", L"Windows Agent Cleanup", MB_OK | MB_ICONERROR);
        return 2;
    }
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    application_state state;
    constexpr wchar_t class_name[] = L"secure_erase_main_window";
    WNDCLASSEXW window_class{};
    window_class.cbSize = static_cast<UINT>(sizeof(window_class));
    window_class.style = CS_CLASSDC;
    window_class.lpfnWndProc = window_procedure;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    const window_icon large_icon(instance, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON));
    const window_icon small_icon(instance, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));
    window_class.hIcon = large_icon.get();
    window_class.hIconSm = small_icon.get();
    window_class.lpszClassName = class_name;
    if (RegisterClassExW(&window_class) == 0)
    {
        MessageBoxW(nullptr, L"Window registration failed.", L"Windows Agent Cleanup", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 2;
    }
    state.window = CreateWindowExW(WS_EX_ACCEPTFILES, class_name, L"Windows Agent Cleanup",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1040, 760,
        nullptr, nullptr, instance, &state);
    if (state.window == nullptr || !create_graphics(state))
    {
        MessageBoxW(nullptr, L"Window or DirectX 11 initialization failed.", L"Windows Agent Cleanup", MB_OK | MB_ICONERROR);
        if (state.window != nullptr)
        {
            DestroyWindow(state.window);
        }
        UnregisterClassW(class_name, instance);
        CoUninitialize();
        return 2;
    }
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    std::array<wchar_t, MAX_PATH> windows_directory{};
    const UINT directory_length = GetWindowsDirectoryW(windows_directory.data(), static_cast<UINT>(windows_directory.size()));
    if (directory_length != 0 && directory_length < windows_directory.size())
    {
        std::wstring font_path = std::wstring(windows_directory.data()) + L"\\Fonts\\msjh.ttc";
        if (GetFileAttributesW(font_path.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            font_path = std::wstring(windows_directory.data()) + L"\\Fonts\\segoeui.ttf";
        }
        auto font_name = frontend::utf8(font_path);
        if (font_name && GetFileAttributesW(font_path.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            // CONTRACT: The current DX11 backend bakes requested glyphs on
            // demand. No legacy full-CJK atlas range is preallocated.
            io.Fonts->AddFontFromFileTTF(font_name->c_str(), 18.0F);
        }
    }
    ImGui::StyleColorsDark();
    const bool win32_initialized = ImGui_ImplWin32_Init(state.window);
    const bool dx11_initialized = win32_initialized && ImGui_ImplDX11_Init(state.device.Get(), state.context.Get());
    if (!dx11_initialized)
    {
        if (win32_initialized)
        {
            ImGui_ImplWin32_Shutdown();
        }
        ImGui::DestroyContext();
        DestroyWindow(state.window);
        UnregisterClassW(class_name, instance);
        CoUninitialize();
        return 2;
    }
    state.imgui_ready = true;
    // SECURITY: Elevated-window drops accept only filenames; no command text is evaluated.
    // UIPI exceptions are scoped to the two messages needed for Explorer file drops.
    ChangeWindowMessageFilterEx(state.window, WM_DROPFILES, MSGFLT_ALLOW, nullptr);
    constexpr UINT copy_global_data_message = 0x0049;
    ChangeWindowMessageFilterEx(state.window, copy_global_data_message, MSGFLT_ALLOW, nullptr);
    DragAcceptFiles(state.window, TRUE);
    ShowWindow(state.window, show_mode);
    UpdateWindow(state.window);
    bool quit{};
    while (!quit)
    {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
            if (message.message == WM_QUIT)
            {
                quit = true;
                break;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        // CONTRACT: Normal frames copy only scalars and immutable plan/report
        // pointers. Potentially large diagnostics are fetched only on demand.
        const auto view = state.app.snapshot(state.details_open || state.failure_popup_open);
        // CONTRACT: Reconcile before the main screen admits queue edits.
        // Drops reconcile separately before admission.
        reconcile_queue(state, view);
        refresh_failures(state, view);
        if (quit || (state.exit_requested && !view.busy))
        {
            break;
        }
        if (state.graphics_failed)
        {
            // CONTRACT: Preserve the event loop while the worker persists its stop.
            MsgWaitForMultipleObjectsEx(0, nullptr, 30, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            continue;
        }
        if (state.pending_width != 0 && state.pending_height != 0)
        {
            state.context->OMSetRenderTargets(0, nullptr, nullptr);
            state.render_target.Reset();
            const HRESULT resized = state.swap_chain->ResizeBuffers(0, state.pending_width,
                state.pending_height, DXGI_FORMAT_UNKNOWN, 0);
            state.pending_width = 0;
            state.pending_height = 0;
            if (FAILED(resized) || !create_render_target(state))
            {
                state.graphics_failed = true;
                state.exit_requested = true;
                state.app.cancel();
                continue;
            }
        }
        if (state.minimized)
        {
            MsgWaitForMultipleObjectsEx(0, nullptr, 30, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            continue;
        }
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        render(state, view);
        ImGui::Render();
        constexpr std::array<float, 4> clear_color{0.065F, 0.075F, 0.10F, 1.0F};
        auto* target = state.render_target.Get();
        state.context->OMSetRenderTargets(1, &target, nullptr);
        state.context->ClearRenderTargetView(target, clear_color.data());
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        const HRESULT presented = state.swap_chain->Present(1, 0);
        if (FAILED(presented))
        {
            state.graphics_failed = true;
            state.exit_requested = true;
            state.app.cancel();
        }
    }
    state.app.cancel();
    state.app.wait();
    state.imgui_ready = false;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    DestroyWindow(state.window);
    UnregisterClassW(class_name, instance);
    CoUninitialize();
    return state.graphics_failed ? 3 : 0;
}
